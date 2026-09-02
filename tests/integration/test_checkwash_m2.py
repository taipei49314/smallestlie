"""Checkwash M2: regression pins + wave2 remainder."""

from __future__ import annotations

from pathlib import Path

import pytest

from smallestlie.campaign.runner import run_campaign
from smallestlie.models import ComparisonResult

ROOT = Path(__file__).resolve().parents[2]
REGRESSION = ["CW-W0-03", "CW-W1-2HOP", "CW-W1-TWIN"]


def _verdicts(summary: dict) -> dict[str, str]:
    return {
        r["attack_id"]: (r.get("comparison") or {}).get("result")
        for r in summary["runs"]
        if not r.get("skipped")
    }


@pytest.mark.integration
def test_regression_pins_stay_false_accept(tmp_path: Path) -> None:
    summary = run_campaign(
        target=ROOT / "fixtures" / "checkwash_target",
        catalog_path=ROOT / "catalogs" / "checkwash-regressions.yaml",
        output_root=tmp_path / "outputs",
        seed=49314,
        adapter_name="checkwash",
        project_root=ROOT,
    )
    assert summary["source_immutable"] is True
    assert summary["ledger_ok"] is True
    by = _verdicts(summary)
    for aid in REGRESSION:
        assert by.get(aid) == ComparisonResult.FALSE_ACCEPT_OBSERVED.value, (aid, by.get(aid))
    assert summary["false_accept_count"] == len(REGRESSION)


@pytest.mark.integration
def test_wave2_justfile_accepted_86d_rejected(tmp_path: Path) -> None:
    summary = run_campaign(
        target=ROOT / "fixtures" / "checkwash_target",
        catalog_path=ROOT / "catalogs" / "checkwash-wave2.yaml",
        output_root=tmp_path / "outputs",
        seed=49314,
        adapter_name="checkwash",
        project_root=ROOT,
    )
    assert summary["ledger_ok"] is True
    by = _verdicts(summary)
    assert by.get("CW-W2-75") == ComparisonResult.FALSE_ACCEPT_OBSERVED.value
    assert by.get("CW-W2-86d") == ComparisonResult.ATTACK_REJECTED.value


@pytest.mark.integration
def test_blind_wave2_false_accepts(tmp_path: Path) -> None:
    summary = run_campaign(
        target=ROOT / "fixtures" / "checkwash_blind",
        catalog_path=ROOT / "catalogs" / "checkwash-wave2.yaml",
        output_root=tmp_path / "outputs",
        seed=49314,
        adapter_name="checkwash_blind",
        project_root=ROOT,
    )
    by = _verdicts(summary)
    assert by.get("CW-W2-75") == ComparisonResult.FALSE_ACCEPT_OBSERVED.value
    assert by.get("CW-W2-86d") == ComparisonResult.FALSE_ACCEPT_OBSERVED.value
