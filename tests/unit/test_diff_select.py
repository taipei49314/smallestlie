"""Diff-aware family selection."""

from __future__ import annotations

from smallestlie.ci.diff_select import families_for_paths, select_attacks_for_diff


def test_families_for_evidence_path() -> None:
    info = families_for_paths(["fixtures/naive_gate/evidence/evidence.json"])
    assert "evidence" in info["families"]


def test_empty_diff_is_full_catalog() -> None:
    r = select_attacks_for_diff(
        ["EXE-003", "AUTH-001"],
        {"EXE-003": "execution", "AUTH-001": "authority"},
        changed_paths=[],
    )
    assert r["mode"] == "full_catalog"
    assert r["selected_attack_ids"] == ["EXE-003", "AUTH-001"]


def test_diff_filters_families_with_smoke() -> None:
    r = select_attacks_for_diff(
        ["EXE-003", "AUTH-001", "PATH-001", "EVD-002"],
        {
            "EXE-003": "execution",
            "AUTH-001": "authority",
            "PATH-001": "path",
            "EVD-002": "evidence",
        },
        changed_paths=["authority/approval.json"],
        include_smoke=True,
    )
    assert r["mode"] == "diff_filtered"
    assert "AUTH-001" in r["selected_attack_ids"]
    # smoke always-include
    assert "EXE-003" in r["selected_attack_ids"]
    assert "PATH-001" not in r["selected_attack_ids"]
    assert "EVD-002" not in r["selected_attack_ids"]


def test_greenwash_and_package_paths() -> None:
    info = families_for_paths(
        [
            "fixtures/greenwash_naive/package/junit/results.xml",
            "fixtures/greenwash_naive/package/subject.json",
        ]
    )
    fams = info["families"]
    assert "execution" in fams or "evidence" in fams
    assert "freshness" in fams or "evidence" in fams


def test_composition_included_when_parent_family_maps() -> None:
    r = select_attacks_for_diff(
        ["PATH-002", "EVD-002", "CMP-001"],
        {
            "PATH-002": "path",
            "EVD-002": "evidence",
            "CMP-001": "composition",
        },
        changed_paths=["protected/required_check.py"],
        attack_specs={
            "CMP-001": {"family": "composition", "parents": ["PATH-002", "EVD-002"]},
        },
        include_smoke=False,
    )
    assert "PATH-002" in r["selected_attack_ids"]
    assert "CMP-001" in r["selected_attack_ids"]
