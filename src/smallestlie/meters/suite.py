"""Measurement suite orchestrator — meter first, then evaluate claim trust."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from smallestlie import __version__
from smallestlie.meters.blindspots import find_blindspots
from smallestlie.meters.campaign_meter import measure_campaign_dir
from smallestlie.meters.catalog_meter import (
    measure_catalog_load,
    measure_composition_presence,
    measure_family_coverage,
    measure_incompleteness_hooks,
    measure_m1_presence,
    measure_oracle_types_used,
)
from smallestlie.meters.ci_meter import measure_ci_artifacts_if_present, measure_status_projection
from smallestlie.meters.claims_registry import evaluate_claim_trust
from smallestlie.meters.containment_meter import measure_policy_surface
from smallestlie.meters.fixture_meter import measure_fixture_matrix
from smallestlie.meters.inventory_meter import measure_source_package_layout, measure_test_surface
from smallestlie.meters.models import Measurement, MeterVerdict
from smallestlie.meters.oracle_meter import (
    measure_oracle_independence_static,
    measure_oracle_plugin_inventory,
)


def run_measurement_suite(
    project_root: str | Path,
    *,
    campaign_dir: str | Path | None = None,
    output_dir: str | Path | None = None,
) -> dict[str, Any]:
    """
    Run all structural meters, optionally campaign meters, then claim trust + blindspots.

    Discipline:
      1) Measure
      2) Only then allow claim trust
      3) Emit blind spots for retest focus
    """
    root = Path(project_root).resolve()
    measurements: list[Measurement] = []

    # --- Structural meters (always) ---
    measurements.append(measure_source_package_layout(root))
    measurements.append(measure_policy_surface())
    measurements.append(measure_family_coverage(root))
    measurements.append(measure_m1_presence(root))
    measurements.append(measure_composition_presence(root))
    measurements.append(measure_catalog_load(root))
    measurements.append(measure_oracle_types_used(root))
    measurements.append(measure_incompleteness_hooks(root))
    measurements.append(measure_oracle_independence_static(root))
    measurements.append(measure_oracle_plugin_inventory(root))
    measurements.append(measure_fixture_matrix(root))
    measurements.append(measure_test_surface(root))
    measurements.append(measure_status_projection())
    measurements.append(measure_ci_artifacts_if_present(root))

    # --- Optional campaign meters ---
    if campaign_dir:
        cdir = Path(campaign_dir)
        if not cdir.is_absolute():
            cdir = (root / cdir).resolve()
        measurements.extend(measure_campaign_dir(cdir))

    m_by_id = {m.meter_id: m.to_dict() for m in measurements}
    claims = evaluate_claim_trust(m_by_id)
    spots = find_blindspots(root, measurements, claims)

    trusted = [c for c in claims if c["trust_allowed"]]
    deferred = [c for c in claims if c.get("deferred")]
    untrusted = [c for c in claims if not c["trust_allowed"] and not c.get("deferred")]

    pass_n = sum(1 for m in measurements if m.verdict == MeterVerdict.MEASURED_PASS)
    fail_n = sum(1 for m in measurements if m.verdict == MeterVerdict.MEASURED_FAIL)
    warn_n = sum(1 for m in measurements if m.verdict == MeterVerdict.MEASURED_WARN)
    not_n = sum(1 for m in measurements if m.verdict == MeterVerdict.NOT_MEASURED)

    high_spots = [s for s in spots if s.severity == "high"]
    med_spots = [s for s in spots if s.severity == "medium"]
    # Hard fail: MEASURED_FAIL or non-deferred untrusted claims
    suite_ok = fail_n == 0 and len(untrusted) == 0
    # Soft: warnings / deferred / medium-or-high blindspots → exit 3 if otherwise ok
    soft = (
        warn_n > 0
        or len(deferred) > 0
        or len(high_spots) > 0
        or len(med_spots) > 0
    )

    if not suite_ok:
        exit_code = 2 if fail_n or untrusted else 3
    elif soft:
        exit_code = 3
    else:
        exit_code = 0

    report: dict[str, Any] = {
        "schema_version": "smallestlie.measurement/v1",
        "tool_version": __version__,
        "measured_at": datetime.now(timezone.utc).isoformat(),
        "project_root": str(root),
        "discipline": [
            "1_measure",
            "2_trust_only_if_meters_pass",
            "3_retest_blindspots",
        ],
        "summary": {
            "measurements": len(measurements),
            "MEASURED_PASS": pass_n,
            "MEASURED_FAIL": fail_n,
            "MEASURED_WARN": warn_n,
            "NOT_MEASURED": not_n,
            "claims_total": len(claims),
            "claims_trusted": len(trusted),
            "claims_deferred": len(deferred),
            "claims_untrusted": len(untrusted),
            "blindspots": len(spots),
            "blindspots_high": len(high_spots),
            "suite_ok": suite_ok,
            "soft_findings": soft,
        },
        "measurements": [m.to_dict() for m in measurements],
        "behavior_claims": claims,
        "trusted_claims": trusted,
        "deferred_claims": deferred,
        "untrusted_claims": untrusted,
        "blindspots": [s.to_dict() for s in spots],
        "language_note": (
            "MEASURED_PASS is not SECURE. Untrusted claims must not be asserted as product truth. "
            "Blind spots are work queue items, not vulnerabilities marketing."
        ),
        "exit_code": exit_code,
    }

    out = Path(output_dir) if output_dir else root / "outputs" / "measurements"
    if not out.is_absolute():
        out = (root / out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / "measurement-report.json"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    md_path = out / "measurement-report.md"
    md_path.write_text(_to_markdown(report), encoding="utf-8")
    report["report_json"] = str(json_path)
    report["report_md"] = str(md_path)
    return report


def _to_markdown(report: dict[str, Any]) -> str:
    s = report.get("summary") or {}
    lines = [
        "# SmallestLie Measurement Report",
        "",
        "> Meter first. Trust behavior only after meters pass. Then retest blind spots.",
        "",
        f"- tool: `{report.get('tool_version')}`",
        f"- measured_at: `{report.get('measured_at')}`",
        f"- suite_ok: `{s.get('suite_ok')}`",
        f"- PASS/FAIL/WARN/NOT_MEASURED: "
        f"`{s.get('MEASURED_PASS')}/{s.get('MEASURED_FAIL')}/{s.get('MEASURED_WARN')}/{s.get('NOT_MEASURED')}`",
        f"- trusted claims: `{s.get('claims_trusted')}/{s.get('claims_total')}`",
        f"- blind spots: `{s.get('blindspots')}` (high=`{s.get('blindspots_high')}`)",
        "",
        "## Discipline",
        "",
    ]
    for d in report.get("discipline") or []:
        lines.append(f"1. `{d}`" if False else f"- `{d}`")
    lines += ["", "## Measurements", ""]
    for m in report.get("measurements") or []:
        lines.append(
            f"- `{m.get('meter_id')}` **{m.get('verdict')}** "
            f"value=`{m.get('value')}` {m.get('unit') or ''}"
        )
    lines += ["", "## Behavior claims (trust gate)", ""]
    for c in report.get("behavior_claims") or []:
        flag = "TRUST" if c.get("trust_allowed") else "DO_NOT_TRUST"
        lines.append(f"- **{flag}** `{c.get('claim_id')}` — {c.get('statement')}")
        lines.append(f"  - reason: {c.get('reason')}")
    lines += ["", "## Blind spots (retest queue)", ""]
    spots = report.get("blindspots") or []
    if not spots:
        lines.append("- (none detected by current instruments)")
    for sp in spots:
        lines.append(
            f"- **{sp.get('severity')}** `{sp.get('spot_id')}` — {sp.get('description')}"
        )
        lines.append(f"  - remediation: {sp.get('remediation')}")
    lines += [
        "",
        "## Language note",
        "",
        report.get("language_note") or "",
        "",
    ]
    return "\n".join(lines)
