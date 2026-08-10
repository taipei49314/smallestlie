from __future__ import annotations

from pathlib import Path
from typing import Any


def write_markdown_report(path: str | Path, summary: dict[str, Any]) -> None:
    p = Path(path)
    lines = [
        f"# SmallestLie Campaign Report",
        "",
        f"- **Campaign ID:** `{summary.get('campaign_id')}`",
        f"- **Status:** `{summary.get('status')}`",
        f"- **Exit code:** `{summary.get('exit_code')}`",
        f"- **Target:** `{summary.get('target', summary.get('error', 'n/a'))}`",
        f"- **False accepts:** `{summary.get('false_accept_count', 0)}`",
        f"- **Source immutable:** `{summary.get('source_immutable', 'n/a')}`",
        f"- **Ledger OK:** `{summary.get('ledger_ok', 'n/a')}`",
        "",
        "## Language note",
        "",
        "This report does **not** claim the target is secure. It only records",
        "observations within the declared campaign boundary.",
        "",
        "## Runs",
        "",
    ]
    for run in summary.get("runs") or []:
        cmp_ = run.get("comparison") or {}
        lines.append(
            f"- `{run.get('run_id')}` **{run.get('attack_id')}** → "
            f"`{cmp_.get('result', 'n/a')}`"
        )
    lines.append("")
    lines.append("## Limitations")
    lines.append("")
    for lim in summary.get("limitations") or []:
        lines.append(f"- {lim}")
    if summary.get("error"):
        lines.append("")
        lines.append("## Error")
        lines.append("")
        lines.append(f"```\n{summary['error']}\n```")
    lines.append("")
    p.write_text("\n".join(lines), encoding="utf-8")
