"""Diff-aware family selection."""

from __future__ import annotations

from smallestlie.ci.diff_select import families_for_paths, select_attacks_for_diff


def test_families_for_evidence_path() -> None:
    fams = families_for_paths(["fixtures/naive_gate/evidence/evidence.json"])
    assert "evidence" in fams


def test_empty_diff_is_full_catalog() -> None:
    r = select_attacks_for_diff(
        ["EXE-003", "AUTH-001"],
        {"EXE-003": "execution", "AUTH-001": "authority"},
        changed_paths=[],
    )
    assert r["mode"] == "full_catalog"
    assert r["selected_attack_ids"] == ["EXE-003", "AUTH-001"]


def test_diff_filters_families() -> None:
    r = select_attacks_for_diff(
        ["EXE-003", "AUTH-001", "PATH-001"],
        {
            "EXE-003": "execution",
            "AUTH-001": "authority",
            "PATH-001": "path",
        },
        changed_paths=["authority/approval.json"],
    )
    assert r["mode"] == "diff_filtered"
    assert "AUTH-001" in r["selected_attack_ids"]
    assert "EXE-003" not in r["selected_attack_ids"]
