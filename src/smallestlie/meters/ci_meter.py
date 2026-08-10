"""CI projection meters."""

from __future__ import annotations

from pathlib import Path

from smallestlie.ci.status import CiProjection, project_campaign_status
from smallestlie.meters.models import Measurement, MeterVerdict


def measure_status_projection() -> Measurement:
    cases = [
        ("skip", dict(campaign_status=None, exit_code=None, ran=False), "failure"),
        ("blocked", dict(campaign_status="BLOCKED", exit_code=4, ran=True), "failure"),
        (
            "fa",
            dict(campaign_status="FAIL_FALSE_ACCEPT_OBSERVED", exit_code=2, ran=True),
            "failure",
        ),
        (
            "pass",
            dict(campaign_status="PASS_NO_FALSE_ACCEPT_OBSERVED", exit_code=0, ran=True),
            "success",
        ),
    ]
    results = {}
    for name, kwargs, expect_gha in cases:
        p = project_campaign_status(**kwargs)
        results[name] = {
            "projection": p.projection.value,
            "gha": p.gha_conclusion,
            "exit_code": p.exit_code,
            "ok": p.gha_conclusion == expect_gha
            and (
                p.gha_conclusion != "success"
                or p.projection == CiProjection.PASS_NO_FALSE_ACCEPT_OBSERVED
            ),
        }
    # Explicit: skip and blocked must not be success
    results["skip"]["ok"] = results["skip"]["gha"] == "failure"
    results["blocked"]["ok"] = results["blocked"]["gha"] == "failure"

    failed = [k for k, v in results.items() if not v["ok"]]
    verdict = MeterVerdict.MEASURED_PASS if not failed else MeterVerdict.MEASURED_FAIL
    return Measurement(
        meter_id="ci.status_projection",
        name="CI status projection anti-theater",
        verdict=verdict,
        value=len(cases) - len(failed),
        evidence={"cases": results, "failed": failed},
    )


def measure_ci_artifacts_if_present(project_root: Path) -> Measurement:
    """Optional: if last ci-summary exists, meter profile expectations structure."""
    candidates = [
        project_root / "outputs" / "ci" / "ci-summary.json",
        project_root / "artifacts" / "smallestlie" / "ci-summary.json",
    ]
    path = next((p for p in candidates if p.is_file()), None)
    if path is None:
        return Measurement(
            meter_id="campaign.ci_profiles_if_present",
            name="CI summary profile expectations (if present)",
            verdict=MeterVerdict.NOT_MEASURED,
            evidence={"note": "no ci-summary.json found; run ci-gate to enable"},
            notes=["NOT_MEASURED is honest incompleteness, not a pass"],
        )

    import json

    data = json.loads(path.read_text(encoding="utf-8"))
    profiles = data.get("profiles") or []
    by_name = {p.get("name"): p for p in profiles if isinstance(p, dict)}
    checks = {
        "has_naive": "naive_expect_false_accept" in by_name,
        "has_honest": "honest_expect_clean" in by_name,
        "naive_met": bool(
            (by_name.get("naive_expect_false_accept") or {}).get("expectation_met")
        ),
        "honest_met": bool((by_name.get("honest_expect_clean") or {}).get("expectation_met")),
        "skipped_not_success": data.get("gha_conclusion") != "success"
        or data.get("projection")
        in {
            "PASS_NO_FALSE_ACCEPT_OBSERVED",
            "PASS_WITH_WARNINGS",
        },
    }
    # If summary claims success, both profiles must be met
    if data.get("exit_code") == 0:
        ok = checks["naive_met"] and checks["honest_met"]
    else:
        ok = True  # failure summaries are still measurable
    verdict = MeterVerdict.MEASURED_PASS if ok and checks["has_naive"] else MeterVerdict.MEASURED_WARN
    return Measurement(
        meter_id="campaign.ci_profiles_if_present",
        name="CI summary profile expectations (if present)",
        verdict=verdict,
        value=data.get("exit_code"),
        evidence={"path": str(path), "checks": checks, "projection": data.get("projection")},
    )
