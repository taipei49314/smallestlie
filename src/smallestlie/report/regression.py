"""Export regression fixtures from confirmed false acceptances."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from smallestlie.attacks.schema import AttackSpec


def export_regression(
    *,
    regressions_dir: Path,
    attack: AttackSpec,
    minimal_mutations: list[dict[str, Any]],
    run_result: dict[str, Any],
    campaign_id: str,
) -> dict[str, Any]:
    regressions_dir.mkdir(parents=True, exist_ok=True)
    name = f"{attack.attack_id}-regression.yaml"
    path = regressions_dir / name
    body = {
        "schema_version": "smallestlie.regression/v1",
        "attack_id": attack.attack_id,
        "campaign_id": campaign_id,
        "expected_future_verdict": "rejected",
        "expected_comparison": "ATTACK_REJECTED",
        "minimal_mutations": minimal_mutations,
        "oracle": attack.oracle,
        "execute": attack.execute,
        "source_finding": {
            "run_id": run_result.get("run_id"),
            "comparison": run_result.get("comparison"),
            "replay": run_result.get("replay"),
        },
        "recommendation": (
            f"Add an invariant so {attack.attack_id} ({attack.name}) is rejected "
            "while valid controls remain accepted."
        ),
    }
    path.write_text(yaml.safe_dump(body, sort_keys=False), encoding="utf-8")

    md_path = regressions_dir / f"{attack.attack_id}-finding.md"
    md_path.write_text(
        "\n".join(
            [
                f"# Finding: {attack.name}",
                "",
                f"- Attack ID: `{attack.attack_id}`",
                f"- Campaign ID: `{campaign_id}`",
                f"- Run ID: `{run_result.get('run_id')}`",
                "",
                "## Claim under test",
                "",
                attack.purpose.strip(),
                "",
                "## Minimal mutation",
                "",
                "```yaml",
                yaml.safe_dump(minimal_mutations, sort_keys=False).rstrip(),
                "```",
                "",
                "## Observed comparison",
                "",
                f"`{(run_result.get('comparison') or {}).get('result')}`",
                "",
                "## Regression recommendation",
                "",
                body["recommendation"],
                "",
                "## Limitations",
                "",
                "- Synthetic fixture finding until revalidated on authorized real targets",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return {
        "exported": True,
        "path": str(path),
        "finding_md": str(md_path),
        "attack_id": attack.attack_id,
    }
