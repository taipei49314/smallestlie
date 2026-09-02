"""Checkwash real-engine campaigns (wave1, beyond-taxonomy)."""

from __future__ import annotations

from pathlib import Path

import pytest

from smallestlie.campaign.runner import run_campaign
from smallestlie.models import ComparisonResult


ROOT = Path(__file__).resolve().parents[2]

REJECTED = [
    "CW-W1-54",
    "CW-W1-77",
    "CW-W1-86a",
    "CW-W1-93",
    "CW-W1-91H",
]
FALSE_ACCEPTED = ["CW-W1-2HOP", "CW-W1-TWIN"]


def _verdicts(summary: dict) -> dict[str, str]:
    return {
        r["attack_id"]: (r.get("comparison") or {}).get("result")
        for r in summary["runs"]
        if not r.get("skipped")
    }


@pytest.mark.integration
def test_real_checkwash_wave1_pins_observed_truth(tmp_path: Path) -> None:
    summary = run_campaign(
        target=ROOT / "fixtures" / "checkwash_target",
        catalog_path=ROOT / "catalogs" / "checkwash-wave1.yaml",
        output_root=tmp_path / "outputs",
        seed=49314,
        adapter_name="checkwash",
        project_root=ROOT,
    )
    assert summary["source_immutable"] is True
    assert summary["ledger_ok"] is True
    by = _verdicts(summary)
    for aid in REJECTED:
        assert by.get(aid) == ComparisonResult.ATTACK_REJECTED.value, (aid, by.get(aid))
    for aid in FALSE_ACCEPTED:
        assert by.get(aid) == ComparisonResult.FALSE_ACCEPT_OBSERVED.value, (aid, by.get(aid))
    assert summary["false_accept_count"] == len(FALSE_ACCEPTED)
    assert summary["inconclusive_count"] == 0


@pytest.mark.integration
def test_blind_engine_false_accepts_wave1(tmp_path: Path) -> None:
    summary = run_campaign(
        target=ROOT / "fixtures" / "checkwash_blind",
        catalog_path=ROOT / "catalogs" / "checkwash-wave1.yaml",
        output_root=tmp_path / "outputs",
        seed=49314,
        adapter_name="checkwash_blind",
        project_root=ROOT,
    )
    assert summary["source_immutable"] is True
    by = _verdicts(summary)
    theater = REJECTED + FALSE_ACCEPTED
    for aid in theater:
        assert by.get(aid) == ComparisonResult.FALSE_ACCEPT_OBSERVED.value, (aid, by.get(aid))
    assert summary["false_accept_count"] == len(theater)
