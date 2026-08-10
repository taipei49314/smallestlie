"""CI gate runner — offline fixture campaigns with budget and honest status."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from smallestlie import __version__
from smallestlie.attacks.catalog import load_catalog
from smallestlie.campaign.runner import run_campaign
from smallestlie.ci.baseline import compare_to_baseline, load_summary
from smallestlie.ci.diff_select import (
    filter_catalog_file,
    load_changed_paths,
    select_attacks_for_diff,
)
from smallestlie.ci.status import CiProjection, project_campaign_status
from smallestlie.ci.summary import stage_artifacts, write_ci_summary, write_github_step_summary
from smallestlie.models import ComparisonResult


@dataclass
class CiProfile:
    name: str
    target: str
    catalog: str
    """Expected outcome class for this profile."""
    expect: str  # fail_false_accept | pass_no_false_accept
    seed: int = 49314
    plan_mode: str | None = None
    required: bool = True


@dataclass
class CiGateConfig:
    profiles: list[CiProfile] = field(default_factory=list)
    budget_seconds: int = 600
    output_root: str = "outputs/ci"
    artifact_dir: str = "artifacts/smallestlie"
    diff_file: str | None = None
    diff_text: str | None = None
    baseline_path: str | None = None
    seed: int = 49314


DEFAULT_PROFILES = [
    CiProfile(
        name="naive_expect_false_accept",
        target="fixtures/naive_gate",
        catalog="catalogs/ci-offline-fast.yaml",
        expect="fail_false_accept",
        seed=49314,
    ),
    CiProfile(
        name="honest_expect_clean",
        target="fixtures/honest_gate",
        catalog="catalogs/ci-offline-fast.yaml",
        expect="pass_no_false_accept",
        seed=49314,
    ),
]


def run_ci_gate(
    *,
    project_root: str | Path,
    config: CiGateConfig | None = None,
    profiles: list[CiProfile] | None = None,
) -> dict[str, Any]:
    """
    Run offline CI gate profiles.

    Exit semantics (top-level):
      0 — all required profiles met expectations; no harness/block/skip
      2 — false-accept expectation failed OR unexpected false accept on clean profile
      3 — warnings / budget
      4 — blocked / skipped not run
      5 — harness error
      6 — invalid config / empty diff selection treated as invalid for required gate
    """
    root = Path(project_root).resolve()
    cfg = config or CiGateConfig()
    profs = profiles or cfg.profiles or list(DEFAULT_PROFILES)
    if not profs:
        return _invalid("no CI profiles configured")

    started = time.monotonic()
    budget = int(cfg.budget_seconds)
    out_root = root / cfg.output_root
    out_root.mkdir(parents=True, exist_ok=True)

    # Diff selection applied to catalogs that support filtering via env file we write
    changed = load_changed_paths(diff_file=cfg.diff_file, diff_text=cfg.diff_text)
    diff_meta: dict[str, Any] | None = None

    profile_results: list[dict[str, Any]] = []
    campaign_dirs: list[str] = []
    any_ran = False
    budget_exceeded = False

    for prof in profs:
        elapsed = time.monotonic() - started
        remaining = budget - elapsed
        if remaining <= 0:
            budget_exceeded = True
            projected = project_campaign_status(
                campaign_status=None,
                exit_code=None,
                ran=False,
                skipped_reason="runtime budget exhausted before profile",
                budget_exceeded=True,
            )
            profile_results.append(
                {
                    "name": prof.name,
                    "required": prof.required,
                    "ran": False,
                    "expect": prof.expect,
                    "expectation_met": False,
                    **projected.to_dict(),
                    "notes": projected.notes + [f"profile_skipped:{prof.name}"],
                }
            )
            continue

        catalog_path = root / prof.catalog
        if not catalog_path.is_file():
            projected = project_campaign_status(
                campaign_status=None,
                exit_code=6,
                ran=False,
                skipped_reason=f"catalog missing: {prof.catalog}",
            )
            profile_results.append(
                {
                    "name": prof.name,
                    "required": prof.required,
                    "ran": False,
                    "expect": prof.expect,
                    "expectation_met": False,
                    **projected.to_dict(),
                    "error": f"catalog missing: {prof.catalog}",
                }
            )
            continue

        # Optional diff filter: write a filtered catalog snapshot for this run
        run_catalog = catalog_path
        try:
            catalog = load_catalog(catalog_path, attacks_root=root / "attacks")
            fam_map = {a.attack_id: a.family for a in catalog.ordered()}
            selection = select_attacks_for_diff(
                catalog.attack_ids,
                fam_map,
                changed_paths=changed,
                attack_specs={
                    a.attack_id: {
                        "family": a.family,
                        "parents": (a.raw or {}).get("parents")
                        or (a.applies_when or {}).get("parent_attacks")
                        or [],
                    }
                    for a in catalog.ordered()
                },
            )
            if diff_meta is None:
                diff_meta = selection
            if selection["mode"] in {"empty_after_diff", "unknown_diff"}:
                projected = project_campaign_status(
                    campaign_status=None,
                    exit_code=None,
                    ran=False,
                    skipped_reason=f"diff selection blocked: {selection['mode']}",
                )
                profile_results.append(
                    {
                        "name": prof.name,
                        "required": prof.required,
                        "ran": False,
                        "expect": prof.expect,
                        "expectation_met": False,
                        **projected.to_dict(),
                        "diff_selection": selection,
                    }
                )
                continue
            if selection["mode"] == "diff_filtered":
                run_catalog = filter_catalog_file(
                    out_root / f"catalog-{prof.name}.yaml",
                    catalog,
                    selection["selected_attack_ids"],
                )
        except Exception as exc:
            projected = project_campaign_status(
                campaign_status="HARNESS_ERROR",
                exit_code=5,
                ran=False,
                skipped_reason=f"catalog/diff error: {exc}",
            )
            profile_results.append(
                {
                    "name": prof.name,
                    "required": prof.required,
                    "ran": False,
                    "expect": prof.expect,
                    "expectation_met": False,
                    **projected.to_dict(),
                    "error": str(exc),
                }
            )
            continue

        # Run campaign
        try:
            summary = run_campaign(
                target=prof.target,
                catalog_path=run_catalog,
                output_root=out_root,
                seed=prof.seed if prof.seed is not None else cfg.seed,
                project_root=root,
                plan_mode=prof.plan_mode,
            )
            any_ran = True
            campaign_dirs.append(str(summary.get("campaign_dir") or ""))
            fa_ids = [
                r.get("attack_id")
                for r in (summary.get("runs") or [])
                if (r.get("comparison") or {}).get("result")
                == ComparisonResult.FALSE_ACCEPT_OBSERVED.value
            ]
            projected = project_campaign_status(
                campaign_status=summary.get("status"),
                exit_code=summary.get("exit_code"),
                ran=True,
                budget_exceeded=False,
            )
            expectation_met = _expectation_met(prof.expect, summary)
            profile_results.append(
                {
                    "name": prof.name,
                    "required": prof.required,
                    "ran": True,
                    "expect": prof.expect,
                    "expectation_met": expectation_met,
                    "campaign_status": summary.get("status"),
                    "campaign_exit_code": summary.get("exit_code"),
                    "false_accept_count": summary.get("false_accept_count", 0),
                    "false_accept_attack_ids": fa_ids,
                    "run_count": len(summary.get("runs") or []),
                    "campaign_dir": summary.get("campaign_dir"),
                    "source_immutable": summary.get("source_immutable"),
                    "ledger_ok": summary.get("ledger_ok"),
                    **projected.to_dict(),
                }
            )
        except Exception as exc:
            projected = project_campaign_status(
                campaign_status="HARNESS_ERROR",
                exit_code=5,
                ran=True,
            )
            profile_results.append(
                {
                    "name": prof.name,
                    "required": prof.required,
                    "ran": True,
                    "expect": prof.expect,
                    "expectation_met": False,
                    **projected.to_dict(),
                    "error": str(exc),
                }
            )

        if time.monotonic() - started > budget:
            budget_exceeded = True

    elapsed = time.monotonic() - started
    if elapsed > budget:
        budget_exceeded = True

    # Aggregate projection
    aggregate = _aggregate_profiles(profile_results, any_ran=any_ran, budget_exceeded=budget_exceeded)

    baseline_compare = None
    if cfg.baseline_path:
        try:
            # Build a comparable current blob
            current_blob = {
                "status": aggregate["projection"],
                "profiles": profile_results,
                "false_accept_attack_ids": _all_fa_ids(profile_results),
            }
            baseline_compare = compare_to_baseline(current_blob, load_summary(cfg.baseline_path))
            if not baseline_compare.get("ok"):
                # Baseline regression forces failure projection
                if aggregate["projection"] in {
                    CiProjection.PASS_NO_FALSE_ACCEPT_OBSERVED.value,
                    CiProjection.PASS_WITH_WARNINGS.value,
                }:
                    aggregate = project_campaign_status(
                        campaign_status="FAIL_FALSE_ACCEPT_OBSERVED",
                        exit_code=2,
                        ran=True,
                        budget_exceeded=budget_exceeded,
                    ).to_dict()
                    aggregate["notes"] = list(aggregate.get("notes") or []) + [
                        "baseline_compare_failed"
                    ]
        except Exception as exc:
            aggregate = project_campaign_status(
                campaign_status="HARNESS_ERROR",
                exit_code=5,
                ran=any_ran,
            ).to_dict()
            aggregate["notes"] = [f"baseline_compare_error:{exc}"]

    ci_summary: dict[str, Any] = {
        "schema_version": "smallestlie.ci_summary/v1",
        "tool_version": __version__,
        "projection": aggregate["projection"],
        "exit_code": aggregate["exit_code"],
        "gha_conclusion": aggregate["gha_conclusion"],
        "badge_label": aggregate["badge_label"],
        "notes": aggregate.get("notes") or [],
        "budget_seconds": budget,
        "elapsed_seconds": round(elapsed, 3),
        "budget_exceeded": budget_exceeded,
        "profiles": profile_results,
        "diff_selection": diff_meta,
        "baseline_compare": baseline_compare,
        "language_note": (
            "No security guarantee. SKIPPED/BLOCKED never count as pass. "
            "False accepts on seeded vulnerable fixtures are expected fail."
        ),
    }

    summary_path = out_root / "ci-summary.json"
    write_ci_summary(summary_path, ci_summary)
    md_path = out_root / "ci-summary.md"
    write_github_step_summary(md_path, ci_summary)

    staging = stage_artifacts(
        staging_dir=root / cfg.artifact_dir,
        campaign_dirs=[d for d in campaign_dirs if d],
        ci_summary_path=summary_path,
    )
    # also copy md into artifacts
    if md_path.is_file():
        (Path(staging["staging_dir"]) / "ci-summary.md").write_text(
            md_path.read_text(encoding="utf-8"), encoding="utf-8"
        )
    ci_summary["artifacts"] = staging
    write_ci_summary(summary_path, ci_summary)
    write_ci_summary(Path(staging["staging_dir"]) / "ci-summary.json", ci_summary)

    return ci_summary


def _expectation_met(expect: str, summary: dict[str, Any]) -> bool:
    """BLOCKED/HARNESS_ERROR never met; missing ledger/immutable never met."""
    status = str(summary.get("status") or "")
    if status in {"BLOCKED", "HARNESS_ERROR"}:
        return False
    if summary.get("exit_code") in {4, 5}:
        return False
    if summary.get("ledger_ok") is not True:
        return False
    if summary.get("source_immutable") is not True:
        return False
    fa = int(summary.get("false_accept_count") or 0)
    if expect == "fail_false_accept":
        return status == "FAIL_FALSE_ACCEPT_OBSERVED" and fa > 0
    if expect == "pass_no_false_accept":
        return status in {"PASS_NO_FALSE_ACCEPT_OBSERVED", "PASS_WITH_WARNINGS"} and fa == 0
    return False


def _aggregate_profiles(
    profiles: list[dict[str, Any]],
    *,
    any_ran: bool,
    budget_exceeded: bool,
) -> dict[str, Any]:
    if not any_ran:
        # If nothing ran, never pass
        return project_campaign_status(
            campaign_status=None,
            exit_code=None,
            ran=False,
            skipped_reason="no profile executed",
            budget_exceeded=budget_exceeded,
        ).to_dict()

    required = [p for p in profiles if p.get("required", True)]
    # Any required profile not meeting expectation → fail
    for p in required:
        if not p.get("ran"):
            return project_campaign_status(
                campaign_status=None,
                exit_code=None,
                ran=False,
                skipped_reason=f"required profile not run: {p.get('name')}",
                budget_exceeded=budget_exceeded,
            ).to_dict()
        if not p.get("expectation_met"):
            # Distinguish unexpected clean on naive vs unexpected FA on honest
            if p.get("expect") == "fail_false_accept":
                return project_campaign_status(
                    campaign_status="HARNESS_ERROR",
                    exit_code=5,
                    ran=True,
                    budget_exceeded=budget_exceeded,
                ).to_dict() | {
                    "notes": [
                        f"expected false accepts on {p.get('name')} but none observed"
                    ]
                }
            # honest got false accepts or bad status
            return project_campaign_status(
                campaign_status="FAIL_FALSE_ACCEPT_OBSERVED",
                exit_code=2,
                ran=True,
                budget_exceeded=budget_exceeded,
            ).to_dict()

    # All required expectations met
    # If naive expected FA and met, that's a successful *gate self-test* contribution;
    # overall CI for the SmallestLie *harness* should still be success when expectations met.
    # Projection: PASS_NO_FALSE_ACCEPT on product under test is about honest profile;
    # for harness CI we report a dedicated note.
    if budget_exceeded:
        return project_campaign_status(
            campaign_status="PASS_WITH_WARNINGS",
            exit_code=3,
            ran=True,
            budget_exceeded=True,
        ).to_dict() | {"notes": ["all required profile expectations met", "budget_exceeded"]}

    return project_campaign_status(
        campaign_status="PASS_NO_FALSE_ACCEPT_OBSERVED",
        exit_code=0,
        ran=True,
    ).to_dict() | {
        "notes": [
            "all required profile expectations met",
            "naive profile expected false accepts (seeded) and observed them",
            "honest profile expected clean and observed clean",
        ]
    }


def _all_fa_ids(profiles: list[dict[str, Any]]) -> list[str]:
    ids: list[str] = []
    for p in profiles:
        for aid in p.get("false_accept_attack_ids") or []:
            if aid and aid not in ids:
                ids.append(str(aid))
    return ids


def _invalid(msg: str) -> dict[str, Any]:
    projected = project_campaign_status(
        campaign_status=None,
        exit_code=6,
        ran=False,
        skipped_reason=msg,
    )
    return {
        "schema_version": "smallestlie.ci_summary/v1",
        "projection": CiProjection.INVALID_CONFIG.value,
        "exit_code": 6,
        "gha_conclusion": "failure",
        "badge_label": "invalid-config",
        "notes": [msg],
        "profiles": [],
        **{k: v for k, v in projected.to_dict().items() if k not in {"projection", "exit_code"}},
    }
