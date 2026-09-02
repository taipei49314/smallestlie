"""Checkwash real-engine campaigns (wave0)."""

from __future__ import annotations

from pathlib import Path

import pytest

from smallestlie.campaign.runner import run_campaign
from smallestlie.models import ComparisonResult


ROOT = Path(__file__).resolve().parents[2]

THEATER_ATTACKS = [
    "CW-W0-01",
    "CW-W0-02",
    "CW-W0-03",  # FA on v0.2.8 (issue #60); rejected since v0.2.9
    "CW-W0-04",
    "CW-W0-05",
    "CW-W0-06",
    "CW-W0-07",
    "CW-W0-08",
]
FALSE_ACCEPTED: list[str] = []
CONTROL = "CW-W0-CTL"


def _verdicts(summary: dict) -> dict[str, str]:
    return {
        r["attack_id"]: (r.get("comparison") or {}).get("result")
        for r in summary["runs"]
        if not r.get("skipped")
    }


@pytest.mark.integration
def test_real_checkwash_rejects_wave0_and_accepts_honest_fix(tmp_path: Path) -> None:
    summary = run_campaign(
        target=ROOT / "fixtures" / "checkwash_target",
        catalog_path=ROOT / "catalogs" / "checkwash-wave0.yaml",
        output_root=tmp_path / "outputs",
        seed=49314,
        adapter_name="checkwash",
        project_root=ROOT,
    )
    assert summary["source_immutable"] is True
    assert summary["ledger_ok"] is True
    by = _verdicts(summary)
    # All eight theater attacks are rejected by the real engine (v0.2.11).
    for aid in THEATER_ATTACKS:
        assert by.get(aid) == ComparisonResult.ATTACK_REJECTED.value, (aid, by.get(aid))
    # The honest fix stays silent — TRUE_ACCEPT is the required outcome.
    assert by.get(CONTROL) == ComparisonResult.TRUE_ACCEPT_OBSERVED.value
    assert summary["false_accept_count"] == len(FALSE_ACCEPTED)
    assert summary["inconclusive_count"] == 0


@pytest.mark.integration
def test_blind_engine_false_accepts_theater(tmp_path: Path) -> None:
    summary = run_campaign(
        target=ROOT / "fixtures" / "checkwash_blind",
        catalog_path=ROOT / "catalogs" / "checkwash-wave0.yaml",
        output_root=tmp_path / "outputs",
        seed=49314,
        adapter_name="checkwash_blind",
        project_root=ROOT,
    )
    assert summary["source_immutable"] is True
    by = _verdicts(summary)
    # The blind engine must accept every theater attack — sensitivity proven.
    for aid in THEATER_ATTACKS:
        assert by.get(aid) == ComparisonResult.FALSE_ACCEPT_OBSERVED.value, (aid, by.get(aid))
    # The honest control is still a TRUE_ACCEPT, even for a blind engine.
    assert by.get(CONTROL) == ComparisonResult.TRUE_ACCEPT_OBSERVED.value
    # The blind engine accepts all eight theater attacks — sensitivity proven.
    assert summary["false_accept_count"] == len(THEATER_ATTACKS) + len(FALSE_ACCEPTED)
    # Internal replays of false accepts must be stable (determinism witness).
    for r in summary["runs"]:
        if (r.get("comparison") or {}).get("result") == ComparisonResult.FALSE_ACCEPT_OBSERVED.value:
            assert r.get("replay", {}).get("stable") is True, r["attack_id"]
