"""Synthetic offline CLI contracts; no live publisher/adoption authority."""

from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

from test_multi_dispatch_witness import (
    export, exported, files, rewrite_report_claim,
)
from test_multi_dispatch_recording_source import publish_j, published
from test_multi_dispatch_recording import record, recorded, reviewed
from multi_dispatch_helpers import (
    approve_reviews, drop_source, ec_context, make_map, make_multi_map, multi_map_templates,
    native_multi, native_templates, plan, report_state,
)
from smallestlie import cli
from smallestlie.campaign.preregistration import PreregistrationError, digest
from smallestlie.models import ExitCode
from smallestlie.report import multi_dispatch_witness as witness
from smallestlie.report.multi_dispatch_witness_view import (
    render_unverified_multi_dispatch_witness,
)


def inspect_cli(root, capsys):
    code = cli.main(["witness", "inspect", str(root)])
    captured = capsys.readouterr()
    return code, json.loads(captured.out), captured


def test_cli_retains_full_selected_roster_and_raw_identifiers(exported, capsys):
    root, _, result = exported
    before = files(root)
    code, view, captured = inspect_cli(root, capsys)
    assert code == 0 and captured.err == ""
    assert view["structural_status"] == "inspected"
    assert view["verification_status"] == "unverified"
    assert view["case_ids"] == ["D", "C"] and view["selected_case_id"] == "D"
    assert view["journal_sha256"] == result.journal_sha256
    assert view["manifest_sha256"] == result.manifest_sha256 == digest(before["manifest.json"])
    assert [row["case_id"] for row in view["claimed_rows"]] == ["D", "C"]
    assert view["claimed_report"]["frozen_case_count"] == 2
    assert files(root) == before


def test_coherent_saved_headline_stays_inside_unverified_claims(exported, capsys):
    root, _, _ = exported
    rewrite_report_claim(root)
    code, view, _ = inspect_cli(root, capsys)
    assert code == 0 and view["verification_status"] == "unverified"
    assert view["claimed_report"]["paired_defect_case_count"] == 999
    assert "paired_defect_case_count" not in view


@pytest.mark.parametrize("state", ["unknown", "kill", "unpaired"])
def test_cli_preserves_missing_evidence_kills_and_separate_counts(tmp_path, native_multi, plan, state, capsys):
    ctx = native_multi(native_change=report_state(plan, "attack", "red")) if state == "kill" else native_multi()
    if state == "unknown":
        for item in ctx["members"]:
            drop_source(ctx, item.slot)
    elif state == "kill":
        for arm in ("repair", "twin"):
            drop_source(ctx, ("D", "runner_command", arm))
    else:
        drop_source(ctx, ("C", "runner_command", "attack"))
    bundle, source = approve_reviews(ctx), tmp_path / "J"
    record(source, bundle, **({"reviews": {}} if state != "unpaired" else {}))
    result = export(tmp_path / "witness", publish_j(source, bundle), selected_case_id="D")
    inspected = witness.inspect_multi_dispatch_witness(result.root)
    code, view, _ = inspect_cli(result.root, capsys)
    assert code == 0 and view["verification_status"] == "unverified"
    assert view["case_ids"] == ["D", "C"] and view["selected_case_id"] == "D"
    assert view["claimed_snapshot"] == inspected.claimed_snapshot
    assert view["claimed_rows"] == list(inspected.claimed_rows)
    assert view["claimed_review_validations"] == list(inspected.claimed_review_validations)
    assert view["claimed_report"] == inspected.claimed_report
    assert view["claimed_report"]["frozen_case_count"] == 2
    assert view["claimed_report"]["paired_defect_case_count"] == 0
    if state != "unpaired":
        assert all(item["state"] == "missing" for item in view["raw_reviews"])
    if state == "unknown":
        assert all(row["verdict"] == "unknown" for row in view["claimed_rows"])
    elif state == "kill":
        assert view["claimed_rows"][0]["verdict"] == "killed_candidate"
    else:
        assert view["claimed_report"]["confirmed_defect_case_count"] == 1


def test_projection_uses_same_acquisition_even_after_bundle_changes(exported, monkeypatch):
    root, _, _ = exported
    original = (root / "manifest.json").read_bytes()
    inspected = witness.inspect_multi_dispatch_witness(root)
    (root / "manifest.json").write_bytes(b"changed after inspection")
    monkeypatch.setattr(witness, "inspect_multi_dispatch_witness", lambda *a: pytest.fail("second acquisition"))
    view = render_unverified_multi_dispatch_witness(inspected)
    assert view["manifest_sha256"] == digest(original)
    assert view["verification_status"] == "unverified"


def test_binary_empty_and_missing_reviews_are_opaque_metadata(exported):
    root, _, _ = exported
    value = witness.inspect_multi_dispatch_witness(root)
    value = replace(value, raw_reviews=(("D", b"\xff\x00bad JSON"), ("C", None), ("empty", b"")),
                    claimed_report={"verification_status": "verified", "structural_status": "passed"})
    view = render_unverified_multi_dispatch_witness(value)
    assert view["verification_status"] == "unverified" and view["structural_status"] == "inspected"
    assert view["claimed_report"]["verification_status"] == "verified"
    assert view["raw_reviews"] == [
        {"case_id": "D", "state": "present", "bytes": 10, "sha256": digest(b"\xff\x00bad JSON")},
        {"case_id": "C", "state": "missing", "bytes": None, "sha256": None},
        {"case_id": "empty", "state": "present", "bytes": 0, "sha256": digest(b"")},
    ]
    json.dumps(view)


def test_renderer_rejects_saved_dict_and_subclass_carriers(exported):
    root, _, _ = exported
    value = witness.inspect_multi_dispatch_witness(root)
    class Fake(witness.UnverifiedMultiDispatchWitness):
        pass
    for fake in (SimpleNamespace(**value.__dict__), value.__dict__, Fake(**value.__dict__)):
        with pytest.raises(TypeError, match="unverified_multi_dispatch_witness_required"):
            render_unverified_multi_dispatch_witness(fake)


def test_offline_cli_has_no_get_adjudication_or_launch(exported, monkeypatch, capsys):
    root, ctx, _ = exported
    def forbidden(*args, **kwargs):
        pytest.fail("offline CLI acquired authority or launched work")
    monkeypatch.setattr(witness, "_acquire_verified_recording", forbidden)
    monkeypatch.setattr(ctx["api"], "workflow_run", forbidden)
    monkeypatch.setattr(cli, "cmd_replay", forbidden)
    monkeypatch.setattr(cli, "cmd_minimize", forbidden)
    monkeypatch.setattr(cli, "run_campaign", forbidden)
    code, view, _ = inspect_cli(root, capsys)
    assert code == 0 and view["verification_status"] == "unverified"


@pytest.mark.parametrize("damage", ["missing", "partial", "extra", "malformed"])
def test_rejected_bundle_is_nonzero_and_never_success(exported, damage, capsys):
    root, _, _ = exported
    if damage == "missing":
        root = root / "does-not-exist"
    elif damage == "partial":
        (root / "manifest.json").unlink()
    elif damage == "extra":
        (root / "extra.txt").write_text("unreferenced", encoding="utf-8")
    else:
        (root / "manifest.json").write_bytes(b"{")
    code, view, _ = inspect_cli(root, capsys)
    assert code == int(ExitCode.INVALID_CONFIG)
    assert view["structural_status"] == "rejected" and view["verification_status"] == "unverified"
    assert view["error_code"] == "witness_inspection_rejected"
    assert "claimed_report" not in view


def test_cli_passes_lexical_path_once_without_resolving(monkeypatch, tmp_path, capsys):
    lexical = str(tmp_path / "linked" / ".." / "bundle")
    calls = []
    def reject(path):
        calls.append(path)
        raise PreregistrationError("linked_path_rejected")
    monkeypatch.setattr(cli, "inspect_multi_dispatch_witness", reject)
    code, view, _ = inspect_cli(lexical, capsys)
    assert calls == [lexical] and code == int(ExitCode.INVALID_CONFIG)
    assert view["verification_status"] == "unverified"


@pytest.mark.parametrize("limit", ["MAX_FILES", "MAX_TOTAL_BYTES", "MAX_ARTIFACT"])
def test_cli_retains_inspector_byte_and_file_bounds(exported, monkeypatch, capsys, limit):
    root, _, _ = exported
    monkeypatch.setattr(witness, limit, 1)
    code, view, _ = inspect_cli(root, capsys)
    assert code == int(ExitCode.INVALID_CONFIG)
    assert view["structural_status"] == "rejected" and view["verification_status"] == "unverified"


def test_cli_error_reason_escapes_control_characters(monkeypatch, tmp_path, capsys):
    def reject(path):
        raise OSError("bad\x1b[31m\x00\npath")
    monkeypatch.setattr(cli, "inspect_multi_dispatch_witness", reject)
    code, view, captured = inspect_cli(tmp_path, capsys)
    assert code == int(ExitCode.INVALID_CONFIG)
    assert "\x1b" not in captured.out and "\x00" not in captured.out
    assert view["reason"] == "bad\x1b[31m\x00\npath"


def test_inspect_help_explains_structural_exit(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["witness", "inspect", "--help"])
    assert exc.value.code == 0
    output = capsys.readouterr().out
    assert "unverified" in output and "exit 0" in output and "structural" in output
