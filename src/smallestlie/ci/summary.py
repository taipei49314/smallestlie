"""Machine-readable CI summary + artifact layout helpers."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any


def write_ci_summary(path: str | Path, summary: dict[str, Any]) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(summary, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    return p


def write_github_step_summary(path: str | Path, summary: dict[str, Any]) -> Path:
    """Markdown suitable for $GITHUB_STEP_SUMMARY."""
    p = Path(path)
    lines = [
        "# SmallestLie CI Gate",
        "",
        f"- **Projection:** `{summary.get('projection')}`",
        f"- **Exit code:** `{summary.get('exit_code')}`",
        f"- **GHA conclusion:** `{summary.get('gha_conclusion')}`",
        f"- **Budget seconds:** `{summary.get('budget_seconds')}`",
        f"- **Elapsed seconds:** `{summary.get('elapsed_seconds')}`",
        f"- **Budget exceeded:** `{summary.get('budget_exceeded')}`",
        "",
        "## Profiles",
        "",
    ]
    for prof in summary.get("profiles") or []:
        lines.append(
            f"- `{prof.get('name')}` → `{prof.get('projection')}` "
            f"(false_accepts={prof.get('false_accept_count', 0)}, "
            f"runs={prof.get('run_count', 0)}, dir=`{prof.get('campaign_dir', '')}`)"
        )
    lines.append("")
    lines.append("## Language note")
    lines.append("")
    lines.append(
        "This gate does **not** claim the product is secure. "
        "Skipped/blocked runs are **failures**, not passes."
    )
    lines.append("")
    if summary.get("diff_selection"):
        ds = summary["diff_selection"]
        lines.append("## Diff selection")
        lines.append("")
        lines.append(f"- mode: `{ds.get('mode')}`")
        lines.append(f"- families: `{', '.join(ds.get('mapped_families') or [])}`")
        lines.append(f"- selected: `{len(ds.get('selected_attack_ids') or [])}`")
        lines.append(f"- excluded: `{len(ds.get('excluded_attack_ids') or [])}`")
        lines.append("")
    if summary.get("baseline_compare"):
        bc = summary["baseline_compare"]
        lines.append("## Baseline compare")
        lines.append("")
        lines.append(f"- ok: `{bc.get('ok')}`")
        lines.append(f"- new false accepts: `{bc.get('new_false_accepts')}`")
        lines.append(f"- resolved: `{bc.get('resolved_false_accepts')}`")
        lines.append("")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(lines), encoding="utf-8")
    return p


def stage_artifacts(
    *,
    staging_dir: str | Path,
    campaign_dirs: list[str | Path],
    ci_summary_path: str | Path,
) -> dict[str, Any]:
    """
    Copy campaign outputs into a stable CI artifact layout:

    artifacts/smallestlie/
      ci-summary.json
      ci-summary.md
      campaigns/<campaign-id>/...
    """
    root = Path(staging_dir)
    root.mkdir(parents=True, exist_ok=True)
    campaigns_root = root / "campaigns"
    campaigns_root.mkdir(exist_ok=True)

    copied: list[str] = []
    for cdir in campaign_dirs:
        src = Path(cdir)
        if not src.is_dir():
            continue
        dest = campaigns_root / src.name
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(
            src,
            dest,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        copied.append(str(dest))

    summary_src = Path(ci_summary_path)
    if summary_src.is_file():
        shutil.copy2(summary_src, root / "ci-summary.json")

    return {
        "staging_dir": str(root),
        "campaigns_copied": copied,
        "layout": [
            "ci-summary.json",
            "ci-summary.md",
            "campaigns/<id>/plan.json",
            "campaigns/<id>/ledger.jsonl",
            "campaigns/<id>/campaign-report.json",
            "campaigns/<id>/runs/",
            "campaigns/<id>/witnesses/",
        ],
    }
