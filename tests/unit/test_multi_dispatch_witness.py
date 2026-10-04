"""Synthetic raw witness contracts, without live publisher or host adoption."""

from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import shutil
import stat
from types import SimpleNamespace

import pytest

from multi_dispatch_helpers import (
    approve_reviews, drop_source, ec_context, make_map, make_multi_map,
    multi_map_templates, native_multi, native_templates, plan, report_state,
)
from test_multi_dispatch_recording import record, recorded, reviewed
from test_multi_dispatch_recording_source import publish_j, published
from smallestlie.campaign.lifecycle import ArtifactStore, encoded
from smallestlie.campaign.preregistration import PreregistrationError, digest
from smallestlie.ledger.multi_dispatch_recording import journal_entry
from smallestlie.report import multi_dispatch_witness as witness


def export(root, ctx, **options):
    bundle = ctx["bundle"]
    return witness.export_multi_dispatch_witness(root, bundle["ctx"]["plan"],
        recording_authority=ctx["authority"], source_authority=bundle["ctx"]["authority"],
        review_authority=bundle["review_authority"], **options)


@pytest.fixture
def exported(tmp_path, published):
    root = tmp_path / "witness"
    result = export(root, published, selected_case_id="D")
    return root, published, result


def manifest(root):
    return json.loads((root / "manifest.json").read_bytes())


def save_manifest(root, value):
    (root / "manifest.json").write_bytes(encoded(value))


def files(root):
    return {str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()}


def rewrite_report_claim(root):
    """Coherent untrusted saved counts must never turn into accepted counts."""
    rows = [json.loads(line) for line in (root / "journal.jsonl").read_bytes().splitlines()]
    old = rows[-1]["payload"]["report"]
    report = json.loads((root / "artifacts" / old["sha256"]).read_bytes())
    report["paired_defect_case_count"] = 999
    raw = encoded(report)
    new = ArtifactStore.reference(raw)
    (root / "artifacts" / new["sha256"]).write_bytes(raw)
    (root / "artifacts" / old["sha256"]).unlink()
    rows[-1]["payload"]["report"] = new
    previous, rebuilt = "0" * 64, []
    for index, row in enumerate(rows, 1):
        entry = journal_entry(index, row["event"], row["payload"], previous)
        previous = entry["entry_sha256"]
        rebuilt.append(encoded(entry) + b"\n")
    journal = b"".join(rebuilt)
    (root / "journal.jsonl").write_bytes(journal)
    value = manifest(root)
    value["journal"]["ref"] = ArtifactStore.reference(journal)
    value["source_hint"]["location"]["journal_sha256"] = digest(journal)
    value["artifacts"] = [{"path": "artifacts/" + path.name, "ref": ArtifactStore.reference(path.read_bytes())}
                          for path in sorted((root / "artifacts").iterdir())]
    save_manifest(root, value)


def test_export_copies_one_fresh_acquisition_and_all_original_bytes(tmp_path, published):
    api = published["api"]
    before = len(api.calls)
    result = export(tmp_path / "witness", published, selected_case_id="D")
    assert api.calls[before:].count(("run", published["root"].repository, 9000, 2)) == 1
    root, value = result.root, manifest(result.root)
    assert result.case_ids == ("D", "C") and value["case_ids"] == ["D", "C"]
    assert result.selected_case_id == value["selected_case_id"] == "D"
    assert (root / "journal.jsonl").read_bytes() == published["files"]["J/journal.jsonl"]
    raw_artifacts = {path.removeprefix("J/"): raw for path, raw in published["files"].items()
                     if path.startswith("J/artifacts/")}
    assert {path: raw for path, raw in files(root).items() if path.startswith("artifacts")} == {
        str(Path(path)): raw for path, raw in raw_artifacts.items()}
    assert {"manifest.json", "README.md", "journal.jsonl"} | {item["path"] for item in value["artifacts"]} == {
        path.replace("\\", "/") for path in files(root)}
    assert result.manifest_sha256 == digest((root / "manifest.json").read_bytes())
    assert "acceptance_ref" not in value["source_hint"]
    assert not any(name.endswith((".py", ".sh", ".ps1")) for name in files(root))


def test_offline_full_roster_raw_reviews_and_counts_are_explicit_claims(exported, monkeypatch):
    root, ctx, result = exported
    def forbidden(*args, **kwargs):
        pytest.fail("offline inspection acquired authority or adjudicated")
    monkeypatch.setattr(witness, "_acquire_verified_recording", forbidden)
    monkeypatch.setattr(ctx["api"], "workflow_run", forbidden)
    inspected = witness.inspect_multi_dispatch_witness(root)
    assert type(inspected) is witness.UnverifiedMultiDispatchWitness
    assert inspected.verification_status == "unverified"
    assert inspected.case_ids == ("D", "C") and inspected.selected_case_id == "D"
    assert inspected.journal_sha256 == result.journal_sha256
    assert dict(inspected.raw_reviews) == ctx["bundle"]["reviews"]
    assert [row["case_id"] for row in inspected.claimed_rows] == ["D", "C"]
    assert inspected.claimed_report["frozen_case_count"] == 2
    assert inspected.claimed_report["paired_defect_case_count"] == 1
    assert "semantic_approval_ref" not in inspected.source_hint


def test_coherent_offline_saved_pass_substitution_stays_unverified(exported, monkeypatch):
    root, ctx, _ = exported
    rewrite_report_claim(root)
    with monkeypatch.context() as patch:
        patch.setattr(witness, "_acquire_verified_recording", lambda *a, **k: pytest.fail("offline authority"))
        inspected = witness.inspect_multi_dispatch_witness(root)
    assert inspected.claimed_report["paired_defect_case_count"] == 999
    assert inspected.verification_status == "unverified"
    rejected = root.parent / "cannot-reexport"
    with pytest.raises(PreregistrationError):
        witness.export_multi_dispatch_witness(rejected, ctx["bundle"]["ctx"]["plan"],
            recording_authority=inspected, source_authority=ctx["bundle"]["ctx"]["authority"])
    assert not rejected.exists()


def test_coherent_case_filter_cannot_contradict_saved_full_rosters(exported):
    root, _, _ = exported
    rows = [json.loads(line) for line in (root / "journal.jsonl").read_bytes().splitlines()]
    rows = [rows[0], rows[1], rows[2], rows[-1]]
    rows[0]["payload"]["case_ids"] = ["D"]
    previous, rebuilt = "0" * 64, []
    for index, row in enumerate(rows, 1):
        entry = journal_entry(index, row["event"], row["payload"], previous)
        previous = entry["entry_sha256"]
        rebuilt.append(encoded(entry) + b"\n")
    journal = b"".join(rebuilt)
    (root / "journal.jsonl").write_bytes(journal)
    used = {ref["sha256"] for row in rows for ref in row["payload"].values()
            if type(ref) is dict and ref.get("state") == "present"}
    for path in (root / "artifacts").iterdir():
        if path.name not in used:
            path.unlink()
    value = manifest(root)
    value["case_ids"] = ["D"]
    value["journal"]["ref"] = ArtifactStore.reference(journal)
    value["source_hint"]["location"]["journal_sha256"] = digest(journal)
    value["artifacts"] = [{"path": "artifacts/" + path.name, "ref": ArtifactStore.reference(path.read_bytes())}
                          for path in sorted((root / "artifacts").iterdir())]
    save_manifest(root, value)
    with pytest.raises(PreregistrationError, match="claimed_roster"):
        witness.inspect_multi_dispatch_witness(root)


def test_closed_j_does_not_lend_revoked_approval_to_export(tmp_path, published):
    authority = published["bundle"]["review_authority"]
    authority.grants = authority.grants[1:]
    root = tmp_path / "revoked"
    with pytest.raises(PreregistrationError, match="recomputed_journal_mismatch"):
        export(root, published)
    assert not root.exists()


def test_exact_j_grant_rejection_creates_no_output(tmp_path, published):
    authority = published["authority"]
    authority.location = replace(published["location"], journal_sha256="0" * 64)
    root = tmp_path / "wrong-j"
    with pytest.raises(PreregistrationError):
        export(root, published)
    assert not root.exists()


def test_selection_keeps_the_full_denominator_and_rejects_unknown_ids(tmp_path, published):
    for selected in ("missing", True, [], "../D"):
        root = tmp_path / ("invalid-" + str(type(selected).__name__))
        with pytest.raises(PreregistrationError, match="selection"):
            export(root, published, selected_case_id=selected)
        assert not root.exists()
    root = tmp_path / "control-view"
    export(root, published, selected_case_id="C")
    result = witness.inspect_multi_dispatch_witness(root)
    assert result.case_ids == ("D", "C") and result.selected_case_id == "C"
    assert result.claimed_report["paired_defect_case_count"] == 1


def test_export_unknown_preserves_missing_raw_reviews_and_source_claims(tmp_path, native_multi):
    ctx = native_multi()
    for item in ctx["members"]:
        drop_source(ctx, item.slot)
    bundle = approve_reviews(ctx)
    source = tmp_path / "unknown-j"
    record(source, bundle, reviews={})
    result = export(tmp_path / "unknown-witness", publish_j(source, bundle))
    inspected = witness.inspect_multi_dispatch_witness(result.root)
    assert inspected.case_ids == ("D", "C")
    assert dict(inspected.raw_reviews) == {"D": None, "C": None}
    assert all(row["verdict"] == "unknown" for row in inspected.claimed_rows)
    assert inspected.claimed_report["paired_defect_case_count"] == 0
    assert inspected.claimed_snapshot["actions"]
    assert all(item["observed"] is None for item in inspected.claimed_snapshot["actions"])


def test_true_kill_with_missing_twin_repair_and_reviews_is_preserved(tmp_path, native_multi, plan):
    ctx = native_multi(native_change=report_state(plan, "attack", "red"))
    for arm in ("repair", "twin"):
        drop_source(ctx, ("D", "runner_command", arm))
    bundle, source = approve_reviews(ctx), tmp_path / "kill-j"
    record(source, bundle, reviews={})
    result = export(tmp_path / "kill-witness", publish_j(source, bundle))
    inspected = witness.inspect_multi_dispatch_witness(result.root)
    assert inspected.claimed_rows[0]["verdict"] == "killed_candidate"
    assert inspected.claimed_report["frozen_case_count"] == 2
    assert inspected.claimed_report["paired_defect_case_count"] == 0
    assert dict(inspected.raw_reviews) == {"D": None, "C": None}


def test_candidate_without_qualified_control_keeps_separate_counts(tmp_path, native_multi):
    ctx = native_multi()
    drop_source(ctx, ("C", "runner_command", "attack"))
    bundle, source = approve_reviews(ctx), tmp_path / "candidate-j"
    record(source, bundle)
    result = export(tmp_path / "candidate-witness", publish_j(source, bundle), selected_case_id="D")
    inspected = witness.inspect_multi_dispatch_witness(result.root)
    assert inspected.claimed_report["confirmed_defect_case_count"] == 1
    assert inspected.claimed_report["paired_defect_case_count"] == 0
    assert inspected.case_ids == ("D", "C")


def test_existing_root_rejects_before_get_and_preserves_every_byte(exported):
    root, ctx, _ = exported
    before, calls = files(root), list(ctx["api"].calls)
    with pytest.raises(PreregistrationError, match="fresh_root"):
        export(root, ctx)
    assert files(root) == before and ctx["api"].calls == calls


def test_export_bounds_reject_before_mkdir(tmp_path, published, monkeypatch):
    for name in ("MAX_FILES", "MAX_TOTAL_BYTES"):
        with monkeypatch.context() as patch:
            patch.setattr(witness, name, 1)
            root = tmp_path / name
            with pytest.raises(PreregistrationError, match="bound"):
                export(root, published)
            assert not root.exists()


def test_interrupted_write_has_no_completion_marker_and_cannot_resume(tmp_path, published, monkeypatch):
    root, original = tmp_path / "interrupted", witness._write_regular
    def fail(path, raw):
        if path.name == "journal.jsonl":
            raise OSError("synthetic storage failure")
        return original(path, raw)
    with monkeypatch.context() as patch:
        patch.setattr(witness, "_write_regular", fail)
        with pytest.raises(OSError, match="synthetic storage"):
            export(root, published)
    assert root.exists() and not (root / "manifest.json").exists()
    with pytest.raises(PreregistrationError):
        witness.inspect_multi_dispatch_witness(root)
    before, calls = files(root), list(published["api"].calls)
    with pytest.raises(PreregistrationError, match="fresh_root"):
        export(root, published)
    assert files(root) == before and published["api"].calls == calls


def test_offline_rejects_closed_inventory_raw_identity_and_journal_damage(exported):
    root, _, _ = exported
    def damage(destination, kind):
        value = manifest(destination)
        if kind == "extra":
            (destination / "replay.py").write_bytes(b"never executable here")
        elif kind == "nested":
            (destination / "artifacts" / "nested").mkdir()
        elif kind == "missing":
            (destination / "artifacts" / value["artifacts"][0]["ref"]["sha256"]).unlink()
        elif kind == "raw":
            (destination / "artifacts" / value["artifacts"][0]["ref"]["sha256"]).write_bytes(b"changed")
        elif kind == "journal":
            path = destination / "journal.jsonl"
            path.write_bytes(path.read_bytes()[:-1])
        elif kind == "readme":
            (destination / "README.md").write_bytes(b"verified")
        elif kind == "duplicate":
            value["artifacts"].append(deepcopy(value["artifacts"][0]))
        elif kind == "roster":
            value["case_ids"] = ["D"]
        elif kind == "selected":
            value["selected_case_id"] = "missing"
        elif kind == "path":
            value["artifacts"][0]["path"] = "../escape"
        elif kind == "grant":
            value["source_hint"]["acceptance_ref"] = "saved grant"
        elif kind == "bool-id":
            value["source_hint"]["run_id"] = True
        else:
            value["verification_status"] = "verified"
        save_manifest(destination, value)
    for kind in ("extra", "nested", "missing", "raw", "journal", "readme", "duplicate",
                 "roster", "selected", "path", "grant", "bool-id", "status"):
        destination = root.parent / ("damaged-" + kind)
        shutil.copytree(root, destination)
        damage(destination, kind)
        with pytest.raises(PreregistrationError):
            witness.inspect_multi_dispatch_witness(destination)


def test_plain_file_rejects_symlink_and_windows_reparse_shape(exported, monkeypatch):
    root, _, _ = exported
    target = root / "journal.jsonl"
    original = Path.lstat
    for mode, attributes in ((stat.S_IFLNK, 0), (stat.S_IFREG, 0x400)):
        def shaped(path, *, _mode=mode, _attributes=attributes):
            if path == target:
                return SimpleNamespace(st_mode=_mode, st_file_attributes=_attributes)
            return original(path)
        with monkeypatch.context() as patch:
            patch.setattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400, raising=False)
            patch.setattr(Path, "lstat", shaped)
            with pytest.raises(PreregistrationError, match="linked/reparse"):
                witness.inspect_multi_dispatch_witness(root)


def test_offline_file_and_aggregate_bounds_reject(exported, monkeypatch):
    root, _, _ = exported
    for name in ("MAX_ARTIFACT", "MAX_FILES", "MAX_TOTAL_BYTES"):
        with monkeypatch.context() as patch:
            patch.setattr(witness, name, 1)
            with pytest.raises(PreregistrationError, match="bound"):
                witness.inspect_multi_dispatch_witness(root)


def test_missing_root_is_a_rejected_incomplete_witness(tmp_path):
    with pytest.raises(PreregistrationError, match="missing_required_root"):
        witness.inspect_multi_dispatch_witness(tmp_path / "missing")
