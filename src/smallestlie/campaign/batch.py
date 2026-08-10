"""Batch campaign runner — multiple authorized local targets in one session."""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from smallestlie import __version__
from smallestlie.attacks.catalog import load_catalog
from smallestlie.campaign.runner import run_campaign
from smallestlie.ci.diff_select import (
    filter_catalog_file,
    load_changed_paths,
    select_attacks_for_diff,
)
from smallestlie.ci.status import project_campaign_status
from smallestlie.models import ComparisonResult


@dataclass
class BatchItem:
    name: str
    target: str
    catalog: str
    adapter: str = "fixture_gate"
    authorization: str | None = None
    seed: int | None = None
    plan_mode: str | None = None
    expect: str | None = None  # fail_false_accept | pass_no_false_accept | any
    required: bool = True
    enabled: bool = True


@dataclass
class BatchConfig:
    items: list[BatchItem] = field(default_factory=list)
    seed: int = 49314
    budget_seconds: int = 3600
    # hard: any budget-not-run required item => exit 4; never soft-pass over budget skips
    budget_mode: str = "hard"  # hard | soft
    output_root: str = "outputs/batch"
    diff_file: str | None = None
    stop_on_required_fail: bool = False
    name: str = "batch"


def load_batch_config(path: str | Path) -> BatchConfig:
    p = Path(path)
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError("batch config must be a mapping")
    body = raw.get("batch", raw)
    if not isinstance(body, dict):
        raise ValueError("batch body must be a mapping")
    items: list[BatchItem] = []
    for i, entry in enumerate(body.get("items") or []):
        if not isinstance(entry, dict):
            raise ValueError(f"batch.items[{i}] must be a mapping")
        items.append(
            BatchItem(
                name=str(entry.get("name") or f"item-{i+1}"),
                target=str(entry["target"]),
                catalog=str(entry.get("catalog") or "catalogs/canonical-m1.yaml"),
                adapter=str(entry.get("adapter") or "fixture_gate"),
                authorization=entry.get("authorization"),
                seed=int(entry["seed"]) if entry.get("seed") is not None else None,
                plan_mode=entry.get("plan_mode"),
                expect=entry.get("expect"),
                required=bool(entry.get("required", True)),
                enabled=bool(entry.get("enabled", True)),
            )
        )
    if not items:
        raise ValueError("batch.items must be non-empty")
    budget_mode = str(body.get("budget_mode") or "hard").lower()
    if budget_mode not in {"hard", "soft"}:
        raise ValueError("batch.budget_mode must be 'hard' or 'soft'")
    return BatchConfig(
        items=items,
        seed=int(body.get("seed", 49314)),
        budget_seconds=int(body.get("budget_seconds", 3600)),
        budget_mode=budget_mode,
        output_root=str(body.get("output_root") or "outputs/batch"),
        diff_file=body.get("diff_file"),
        stop_on_required_fail=bool(body.get("stop_on_required_fail", False)),
        name=str(body.get("name") or p.stem),
    )


def run_batch(
    *,
    project_root: str | Path,
    config: BatchConfig,
    diff_file: str | Path | None = None,
) -> dict[str, Any]:
    """
    Run campaigns for each batch item under a wall-clock budget.

    Exit codes (top-level):
      0 — all required items ran and met expectations
      2 — required item unexpected false-accept / expectation fail
      3 — soft budget warnings only when budget_mode=soft and all required met
      4 — required item not run / blocked / disabled / hard budget skip
      5 — harness error
      6 — invalid config
    """
    root = Path(project_root).resolve()
    started = time.monotonic()
    budget = int(config.budget_seconds)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
    batch_id = f"BATCH-{config.name}-{ts}-{uuid.uuid4().hex[:8]}"
    out_root = Path(config.output_root)
    if not out_root.is_absolute():
        out_root = (root / out_root).resolve()
    batch_dir = out_root / batch_id
    batch_dir.mkdir(parents=True, exist_ok=True)

    diff_path = diff_file or config.diff_file
    changed = load_changed_paths(diff_file=diff_path)
    results: list[dict[str, Any]] = []
    budget_exceeded = False
    budget_skipped_required = False

    for item in config.items:
        if not item.enabled:
            # P0: required + disabled => NOT_RUN failure (never pass)
            proj = project_campaign_status(
                campaign_status=None,
                exit_code=None,
                ran=False,
                skipped_reason="required item disabled" if item.required else "disabled",
            )
            results.append(
                {
                    "name": item.name,
                    "enabled": False,
                    "ran": False,
                    "required": item.required,
                    "skipped_reason": "disabled in batch config",
                    "expect": item.expect,
                    "expectation_met": False if item.required else True,
                    "not_run": True,
                    **proj.to_dict(),
                }
            )
            continue

        elapsed = time.monotonic() - started
        remaining = budget - elapsed
        if remaining <= 0:
            budget_exceeded = True
            if item.required:
                budget_skipped_required = True
            proj = project_campaign_status(
                campaign_status=None,
                exit_code=None,
                ran=False,
                skipped_reason="batch budget exhausted (hard wall-clock)",
                budget_exceeded=True,
            )
            results.append(
                {
                    "name": item.name,
                    "enabled": True,
                    "ran": False,
                    "required": item.required,
                    "expect": item.expect,
                    "expectation_met": False if item.required else True,
                    "not_run": True,
                    "budget_skipped": True,
                    **proj.to_dict(),
                }
            )
            if item.required and config.stop_on_required_fail:
                break
            continue

        catalog_path = Path(item.catalog)
        if not catalog_path.is_absolute():
            catalog_path = root / catalog_path
        if not catalog_path.is_file():
            proj = project_campaign_status(
                campaign_status=None,
                exit_code=6,
                ran=False,
                skipped_reason=f"catalog missing: {item.catalog}",
            )
            results.append(
                {
                    "name": item.name,
                    "enabled": True,
                    "ran": False,
                    "required": item.required,
                    "expectation_met": False,
                    "error": f"catalog missing: {item.catalog}",
                    **proj.to_dict(),
                }
            )
            if item.required and config.stop_on_required_fail:
                break
            continue

        run_catalog = catalog_path
        item_diff: dict[str, Any] | None = None
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
            item_diff = selection
            if selection["mode"] in {"empty_after_diff", "unknown_diff"}:
                proj = project_campaign_status(
                    campaign_status=None,
                    exit_code=None,
                    ran=False,
                    skipped_reason=f"diff selection blocked: {selection['mode']}",
                )
                results.append(
                    {
                        "name": item.name,
                        "enabled": True,
                        "ran": False,
                        "required": item.required,
                        "expectation_met": False if item.required else True,
                        "diff_selection": selection,
                        **proj.to_dict(),
                    }
                )
                if item.required and config.stop_on_required_fail:
                    break
                continue
            if selection["mode"] == "diff_filtered":
                run_catalog = filter_catalog_file(
                    batch_dir / f"catalog-{item.name}.yaml",
                    catalog,
                    selection["selected_attack_ids"],
                )
        except Exception as exc:
            results.append(
                {
                    "name": item.name,
                    "enabled": True,
                    "ran": False,
                    "required": item.required,
                    "expectation_met": False,
                    "error": f"diff/catalog error: {exc}",
                    "projection": "HARNESS_ERROR",
                    "exit_code": 5,
                    "gha_conclusion": "failure",
                    "campaign_status": "HARNESS_ERROR",
                }
            )
            if item.required and config.stop_on_required_fail:
                break
            continue

        try:
            summary = run_campaign(
                target=item.target,
                catalog_path=run_catalog,
                output_root=batch_dir / "campaigns",
                seed=item.seed if item.seed is not None else config.seed,
                adapter_name=item.adapter,
                authorization_path=item.authorization,
                project_root=root,
                plan_mode=item.plan_mode,
            )
            fa_ids = [
                r.get("attack_id")
                for r in (summary.get("runs") or [])
                if (r.get("comparison") or {}).get("result")
                == ComparisonResult.FALSE_ACCEPT_OBSERVED.value
            ]
            met = _expectation_met(item.expect, summary)
            proj = project_campaign_status(
                campaign_status=summary.get("status"),
                exit_code=summary.get("exit_code"),
                ran=True,
            )
            # Integrity: BLOCKED/HARNESS_ERROR can never be expectation_met
            status = str(summary.get("status") or "")
            if status in {"BLOCKED", "HARNESS_ERROR"} or int(summary.get("exit_code") or 0) in {
                4,
                5,
            }:
                met = False
            results.append(
                {
                    "name": item.name,
                    "enabled": True,
                    "ran": True,
                    "required": item.required,
                    "target": item.target,
                    "adapter": item.adapter,
                    "catalog": item.catalog,
                    "expect": item.expect,
                    "expectation_met": met,
                    "campaign_id": summary.get("campaign_id"),
                    "campaign_dir": summary.get("campaign_dir"),
                    "campaign_status": summary.get("status"),
                    "false_accept_count": summary.get("false_accept_count", 0),
                    "false_accept_attack_ids": fa_ids,
                    "run_count": len(summary.get("runs") or []),
                    "source_immutable": summary.get("source_immutable"),
                    "ledger_ok": summary.get("ledger_ok"),
                    "diff_selection": item_diff,
                    **proj.to_dict(),
                }
            )
            if item.required and not met and config.stop_on_required_fail:
                break
        except Exception as exc:
            results.append(
                {
                    "name": item.name,
                    "enabled": True,
                    "ran": True,
                    "required": item.required,
                    "expectation_met": False,
                    "error": str(exc),
                    "projection": "HARNESS_ERROR",
                    "campaign_status": "HARNESS_ERROR",
                    "exit_code": 5,
                    "gha_conclusion": "failure",
                    "diff_selection": item_diff,
                }
            )
            if item.required and config.stop_on_required_fail:
                break

        if time.monotonic() - started >= budget:
            budget_exceeded = True

    elapsed = time.monotonic() - started
    if elapsed > budget:
        budget_exceeded = True

    aggregate = _aggregate(
        results,
        budget_exceeded=budget_exceeded,
        budget_skipped_required=budget_skipped_required,
        budget_mode=config.budget_mode,
    )
    report = {
        "schema_version": "smallestlie.batch/v1",
        "batch_id": batch_id,
        "name": config.name,
        "tool_version": __version__,
        "seed": config.seed,
        "budget_seconds": budget,
        "budget_mode": config.budget_mode,
        "elapsed_seconds": round(elapsed, 3),
        "budget_exceeded": budget_exceeded,
        "budget_skipped_required": budget_skipped_required,
        "projection": aggregate["projection"],
        "exit_code": aggregate["exit_code"],
        "gha_conclusion": aggregate["gha_conclusion"],
        "items": results,
        "batch_dir": str(batch_dir),
        "language_note": (
            "Batch results are campaign-bounded. "
            "BLOCKED/HARNESS_ERROR/required-disabled/missing ledger or immutability never pass. "
            "Not a security guarantee."
        ),
    }
    (batch_dir / "batch-report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8"
    )
    (batch_dir / "batch-report.md").write_text(_batch_md(report), encoding="utf-8")
    report["report_json"] = str(batch_dir / "batch-report.json")
    report["report_md"] = str(batch_dir / "batch-report.md")
    return report


def _expectation_met(expect: str | None, summary: dict[str, Any]) -> bool:
    """
    Integrity rules:
    - BLOCKED / HARNESS_ERROR => never met
    - missing ledger_ok or source_immutable (None/absent/False) => never met
    """
    status = str(summary.get("status") or "")
    exit_code = summary.get("exit_code")
    if status in {"BLOCKED", "HARNESS_ERROR"}:
        return False
    if exit_code in {4, 5}:
        return False
    # missing keys fail closed
    if summary.get("ledger_ok") is not True:
        return False
    if summary.get("source_immutable") is not True:
        return False

    fa = int(summary.get("false_accept_count") or 0)
    if not expect or expect == "any":
        return True
    if expect == "fail_false_accept":
        # Must be the dedicated FA status (not FA mixed with harness collapse)
        return status == "FAIL_FALSE_ACCEPT_OBSERVED" and fa > 0
    if expect == "pass_no_false_accept":
        return status in {"PASS_NO_FALSE_ACCEPT_OBSERVED", "PASS_WITH_WARNINGS"} and fa == 0
    return False


def _aggregate(
    results: list[dict[str, Any]],
    *,
    budget_exceeded: bool,
    budget_skipped_required: bool,
    budget_mode: str,
) -> dict[str, Any]:
    # All required items (including disabled/not-run) are integrity-relevant.
    required = [r for r in results if r.get("required", True)]
    if not required:
        return project_campaign_status(
            campaign_status=None,
            exit_code=6,
            ran=False,
            skipped_reason="no required batch items",
        ).to_dict()

    for r in required:
        # required + disabled or not run
        if r.get("enabled") is False or not r.get("ran"):
            return project_campaign_status(
                campaign_status=None,
                exit_code=None,
                ran=False,
                skipped_reason=f"required item not run: {r.get('name')}",
                budget_exceeded=budget_exceeded or bool(r.get("budget_skipped")),
            ).to_dict()
        status = str(r.get("campaign_status") or r.get("projection") or "")
        if status in {"BLOCKED", "HARNESS_ERROR", "BLOCKED_BY_POLICY"} or r.get(
            "exit_code"
        ) in {4, 5}:
            return project_campaign_status(
                campaign_status="HARNESS_ERROR"
                if "HARNESS" in status or r.get("exit_code") == 5
                else "BLOCKED",
                exit_code=5 if r.get("exit_code") == 5 or "HARNESS" in status else 4,
                ran=True,
                budget_exceeded=budget_exceeded,
            ).to_dict()
        if r.get("expectation_met") is False:
            if r.get("expect") == "fail_false_accept":
                return project_campaign_status(
                    campaign_status="HARNESS_ERROR",
                    exit_code=5,
                    ran=True,
                    budget_exceeded=budget_exceeded,
                ).to_dict() | {"notes": [f"expected false accepts missing: {r.get('name')}"]}
            if int(r.get("false_accept_count") or 0) > 0 or r.get(
                "campaign_status"
            ) == "FAIL_FALSE_ACCEPT_OBSERVED":
                return project_campaign_status(
                    campaign_status="FAIL_FALSE_ACCEPT_OBSERVED",
                    exit_code=2,
                    ran=True,
                    budget_exceeded=budget_exceeded,
                ).to_dict()
            return project_campaign_status(
                campaign_status="HARNESS_ERROR",
                exit_code=5,
                ran=True,
                budget_exceeded=budget_exceeded,
            ).to_dict()

    # Hard budget: any required skip due to budget already returned above.
    # If we finished all required but wall clock exceeded:
    if budget_exceeded or budget_skipped_required:
        if budget_mode == "hard" and budget_skipped_required:
            return project_campaign_status(
                campaign_status=None,
                exit_code=None,
                ran=False,
                skipped_reason="hard budget skipped required items",
                budget_exceeded=True,
            ).to_dict()
        return project_campaign_status(
            campaign_status="PASS_WITH_WARNINGS",
            exit_code=3,
            ran=True,
            budget_exceeded=True,
        ).to_dict()

    return project_campaign_status(
        campaign_status="PASS_NO_FALSE_ACCEPT_OBSERVED",
        exit_code=0,
        ran=True,
    ).to_dict() | {"notes": ["all required batch expectations met"]}


def _batch_md(report: dict[str, Any]) -> str:
    lines = [
        f"# Batch Report: {report.get('batch_id')}",
        "",
        f"- projection: `{report.get('projection')}`",
        f"- exit_code: `{report.get('exit_code')}`",
        f"- budget_mode: `{report.get('budget_mode')}`",
        f"- budget_exceeded: `{report.get('budget_exceeded')}`",
        f"- elapsed_seconds: `{report.get('elapsed_seconds')}`",
        "",
        "## Items",
        "",
    ]
    for item in report.get("items") or []:
        lines.append(
            f"- **{item.get('name')}** ran=`{item.get('ran')}` "
            f"enabled=`{item.get('enabled')}` "
            f"expect_met=`{item.get('expectation_met')}` "
            f"FA=`{item.get('false_accept_count', 'n/a')}` "
            f"status=`{item.get('campaign_status') or item.get('projection')}`"
        )
        ds = item.get("diff_selection")
        if isinstance(ds, dict):
            lines.append(
                f"  - diff: mode=`{ds.get('mode')}` "
                f"selected={len(ds.get('selected_attack_ids') or [])} "
                f"families=`{ds.get('mapped_families')}`"
            )
    lines += ["", report.get("language_note") or "", ""]
    return "\n".join(lines)
