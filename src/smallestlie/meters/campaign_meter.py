"""Meters over an existing campaign output directory."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from smallestlie.meters.models import Measurement, MeterVerdict
from smallestlie.models import ComparisonResult


def measure_campaign_dir(campaign_dir: Path) -> list[Measurement]:
    """Compute North-Star-aligned metrics for one campaign folder."""
    report_path = campaign_dir / "campaign-report.json"
    if not report_path.is_file():
        return [
            Measurement(
                meter_id="campaign.report_present",
                name="Campaign report present",
                verdict=MeterVerdict.NOT_MEASURED,
                evidence={"campaign_dir": str(campaign_dir)},
            )
        ]

    report = json.loads(report_path.read_text(encoding="utf-8"))
    runs = report.get("runs") or []
    measurements: list[Measurement] = []

    # False-accept yield
    fa = [
        r
        for r in runs
        if (r.get("comparison") or {}).get("result")
        == ComparisonResult.FALSE_ACCEPT_OBSERVED.value
    ]
    fa_ids = sorted({r.get("attack_id") for r in fa if r.get("attack_id")})
    measurements.append(
        Measurement(
            meter_id="campaign.false_accept_yield",
            name="Confirmed false-acceptance yield (unique attack ids)",
            verdict=MeterVerdict.MEASURED_PASS,  # informational; no universal threshold
            value=len(fa_ids),
            unit="unique_attacks",
            evidence={"attack_ids": fa_ids, "status": report.get("status")},
            notes=["informational meter — high yield is not automatically good"],
        )
    )

    # Rejection rate among invalid worlds (oracle valid false)
    invalid = []
    rejected = []
    for r in runs:
        if r.get("skipped"):
            continue
        oracle = r.get("oracle") or {}
        if oracle.get("valid") is False:
            invalid.append(r)
            if (r.get("comparison") or {}).get("result") == ComparisonResult.ATTACK_REJECTED.value:
                rejected.append(r)
    rate = (len(rejected) / len(invalid)) if invalid else None
    measurements.append(
        Measurement(
            meter_id="campaign.mutation_rejection_rate",
            name="Mutation rejection rate (invalid worlds)",
            verdict=MeterVerdict.MEASURED_PASS if rate is not None else MeterVerdict.NOT_MEASURED,
            value=None if rate is None else round(rate, 4),
            unit="ratio",
            evidence={
                "invalid_world_runs": len(invalid),
                "attack_rejected": len(rejected),
            },
        )
    )

    # Reproduction rate among FA with replay
    with_replay = [r for r in fa if r.get("replay")]
    stable = [r for r in with_replay if (r.get("replay") or {}).get("stable")]
    repro = (len(stable) / len(with_replay)) if with_replay else None
    measurements.append(
        Measurement(
            meter_id="campaign.reproduction_rate",
            name="FA witness reproduction rate",
            verdict=(
                MeterVerdict.MEASURED_PASS
                if repro == 1.0
                else (
                    MeterVerdict.MEASURED_FAIL
                    if repro is not None and repro < 1.0
                    else MeterVerdict.NOT_MEASURED
                )
            ),
            value=repro,
            unit="ratio",
            threshold={"min": 1.0},
            evidence={
                "fa_with_replay": len(with_replay),
                "stable": len(stable),
                "unstable_ids": [
                    r.get("attack_id")
                    for r in with_replay
                    if not (r.get("replay") or {}).get("stable")
                ],
            },
        )
    )

    # Minimization ratios
    ratios = []
    for r in fa:
        m = r.get("minimization") or {}
        o = m.get("original_steps")
        n = m.get("minimal_steps")
        if isinstance(o, int) and isinstance(n, int) and o > 0:
            ratios.append({"attack_id": r.get("attack_id"), "ratio": n / o, "original": o, "minimal": n})
    avg = sum(x["ratio"] for x in ratios) / len(ratios) if ratios else None
    measurements.append(
        Measurement(
            meter_id="campaign.minimization_ratio",
            name="Average minimization ratio (minimal/original)",
            verdict=MeterVerdict.MEASURED_PASS if ratios else MeterVerdict.NOT_MEASURED,
            value=None if avg is None else round(avg, 4),
            unit="ratio",
            evidence={"per_attack": ratios},
            notes=["lower is better when reproducibility holds"],
        )
    )

    # Regression conversion
    exported = [r for r in fa if (r.get("regression") or {}).get("exported")]
    conv = (len(exported) / len(fa)) if fa else None
    measurements.append(
        Measurement(
            meter_id="campaign.regression_conversion",
            name="Regression conversion rate for FA",
            verdict=(
                MeterVerdict.MEASURED_PASS
                if conv == 1.0
                else (
                    MeterVerdict.MEASURED_WARN
                    if conv is not None
                    else MeterVerdict.NOT_MEASURED
                )
            ),
            value=conv,
            unit="ratio",
            threshold={"target": 1.0},
            evidence={"fa": len(fa), "exported": len(exported)},
        )
    )

    # Honest incompleteness counts
    incompleteness: dict[str, int] = {}
    for r in runs:
        res = (r.get("comparison") or {}).get("result") or "UNKNOWN"
        if res in {
            "INCONCLUSIVE",
            "INAPPLICABLE",
            "BLOCKED_BY_POLICY",
            "HARNESS_ERROR",
            "NOT_RUN",
        } or r.get("skipped"):
            key = res if not r.get("skipped") else "SKIPPED"
            incompleteness[key] = incompleteness.get(key, 0) + 1
    measurements.append(
        Measurement(
            meter_id="campaign.incompleteness",
            name="Honest incompleteness counters",
            verdict=MeterVerdict.MEASURED_PASS,
            value=sum(incompleteness.values()),
            unit="runs",
            evidence={"counts": incompleteness},
            notes=["presence of zeros is fine; hiding these keys would be a blind spot"],
        )
    )

    # Source immutability + ledger
    measurements.append(
        Measurement(
            meter_id="campaign.source_immutable",
            name="Source immutable flag",
            verdict=(
                MeterVerdict.MEASURED_PASS
                if report.get("source_immutable") is True
                else MeterVerdict.MEASURED_FAIL
            ),
            value=report.get("source_immutable"),
            evidence={
                "before": report.get("source_digest_before"),
                "after": report.get("source_digest_after"),
            },
        )
    )
    measurements.append(
        Measurement(
            meter_id="campaign.ledger_ok",
            name="Ledger verification flag",
            verdict=(
                MeterVerdict.MEASURED_PASS
                if report.get("ledger_ok") is True
                else MeterVerdict.MEASURED_FAIL
            ),
            value=report.get("ledger_ok"),
        )
    )

    return measurements
