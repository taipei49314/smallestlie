"""Measurement suite and blind-spot tests."""

from __future__ import annotations

from pathlib import Path

from smallestlie.ci.status import project_campaign_status
from smallestlie.meters.claims_registry import evaluate_claim_trust
from smallestlie.meters.containment_meter import measure_policy_surface
from smallestlie.meters.suite import run_measurement_suite


ROOT = Path(__file__).resolve().parents[2]


def test_containment_meter_passes() -> None:
    m = measure_policy_surface()
    assert m.verdict.value == "MEASURED_PASS"


def test_claim_trust_requires_pass() -> None:
    claims = evaluate_claim_trust(
        {
            "containment.policy_surface": {"verdict": "MEASURED_PASS"},
            "inventory.test_surface": {"verdict": "MEASURED_FAIL"},
        }
    )
    by = {c["claim_id"]: c for c in claims}
    # containment claim needs both containment + test surface
    assert by["containment.path_and_source"]["trust_allowed"] is False


def test_measurement_suite_runs(tmp_path: Path) -> None:
    report = run_measurement_suite(ROOT, output_dir=tmp_path / "m")
    assert "measurements" in report
    assert report["summary"]["measurements"] >= 10
    assert (tmp_path / "m" / "measurement-report.json").is_file()
    # No hard untrusted if suite healthy
    assert report["summary"]["MEASURED_FAIL"] == 0
    ids = {m["meter_id"] for m in report["measurements"]}
    assert "containment.policy_surface" in ids
    assert "catalog.m1_minimum" in ids


def test_skipped_projection_still_failure() -> None:
    p = project_campaign_status(campaign_status=None, exit_code=None, ran=False)
    assert p.gha_conclusion == "failure"
