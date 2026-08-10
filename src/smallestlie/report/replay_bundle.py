from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from smallestlie.attacks.schema import AttackSpec


def write_replay_bundle(
    *,
    witness_dir: Path,
    attack: AttackSpec,
    run_result: dict[str, Any],
    baseline: dict[str, Any],
    authorization_digest: str,
    source_fixture_name: str,
) -> None:
    witness_dir.mkdir(parents=True, exist_ok=True)
    (witness_dir / "minimized-attack.yaml").write_text(
        yaml.safe_dump(attack.to_dict(), sort_keys=False),
        encoding="utf-8",
    )
    (witness_dir / "evidence-manifest.json").write_text(
        json.dumps(
            {
                "attack_id": attack.attack_id,
                "authorization_digest": authorization_digest,
                "baseline_digest": baseline.get("baseline_digest"),
                "comparison": run_result.get("comparison"),
                "source_fixture_name": source_fixture_name,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    # Portable replay helper (local fixture only).
    script = f"""#!/usr/bin/env bash
# Replay witness for {attack.attack_id}
# Authorized local synthetic fixture / disposable clone only.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
uv run smallestlie replay "$(cd "$(dirname "$0")" && pwd)"
"""
    (witness_dir / "replay.sh").write_text(script, encoding="utf-8")
    ps = f"""# Replay witness for {attack.attack_id}
# Authorized local synthetic fixture / disposable clone only.
$Witness = $PSScriptRoot
Set-Location (Resolve-Path "$Witness\\..\\..\\..")
uv run smallestlie replay $Witness
"""
    (witness_dir / "replay.ps1").write_text(ps, encoding="utf-8")
    (witness_dir / "README.md").write_text(
        "\n".join(
            [
                f"# Witness: {attack.attack_id}",
                "",
                "This package reproduces a confirmed false acceptance against an",
                "authorized local fixture. It does not target remote systems.",
                "",
                "## Reproduce",
                "",
                "```bash",
                "smallestlie replay <this-directory>",
                "```",
                "",
                "## Limitations",
                "",
                "- Synthetic fixture context",
                "- Relative paths only; no host secrets",
                "",
            ]
        ),
        encoding="utf-8",
    )
