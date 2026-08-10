"""Diff-aware attack family selection for CI budgets."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any


# Path glob-ish patterns → attack families (trust-surface map for synthetic + future adapters)
_SURFACE_RULES: list[tuple[re.Pattern[str], set[str]]] = [
    (re.compile(r"(^|/)(evidence|artifacts|attestations?)(/|$)", re.I), {"evidence", "freshness"}),
    (re.compile(r"(^|/)(tests?|pytest|junit)(/|$)", re.I), {"execution", "evidence"}),
    (re.compile(r"(^|/)(workflow|\.github|ci)(/|$)", re.I), {"workflow", "projection"}),
    (re.compile(r"(^|/)(policy|gate_policy|config)(/|$)", re.I), {"config", "semantic"}),
    (re.compile(r"(^|/)(authority|approval|actor)(/|$)", re.I), {"authority"}),
    (re.compile(r"(^|/)(protected|identity|path)(/|$)", re.I), {"path"}),
    (re.compile(r"(^|/)(report|projection|summary)(/|$)", re.I), {"projection"}),
    (re.compile(r"(^|/)(verifier|oracle)(/|$)", re.I), {"verifier", "semantic"}),
    (re.compile(r"(^|/)(revision|REVISION)", re.I), {"freshness", "evidence"}),
]


def families_for_paths(paths: list[str]) -> set[str]:
    """Map changed paths to attack families."""
    families: set[str] = set()
    for raw in paths:
        p = raw.replace("\\", "/").lstrip("./")
        for pattern, fams in _SURFACE_RULES:
            if pattern.search(p):
                families |= fams
    return families


def parse_diff_name_only(text: str) -> list[str]:
    """Parse `git diff --name-only` style output."""
    paths: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            paths.append(line)
    return paths


def load_changed_paths(
    *,
    diff_file: str | Path | None = None,
    diff_text: str | None = None,
    paths: list[str] | None = None,
) -> list[str]:
    if paths:
        return list(paths)
    if diff_text:
        return parse_diff_name_only(diff_text)
    if diff_file:
        p = Path(diff_file)
        if p.is_file():
            return parse_diff_name_only(p.read_text(encoding="utf-8"))
    return []


def select_attacks_for_diff(
    attack_ids: list[str],
    attack_families: dict[str, str],
    *,
    changed_paths: list[str],
    always_include: list[str] | None = None,
    default_families: set[str] | None = None,
) -> dict[str, Any]:
    """
    Filter attack ids by families implied by changed paths.

    If no paths provided, keep all (full catalog) and mark selection as full.
    """
    always = set(always_include or [])
    if not changed_paths:
        return {
            "mode": "full_catalog",
            "changed_paths": [],
            "mapped_families": sorted(default_families or set(attack_families.values())),
            "selected_attack_ids": list(attack_ids),
            "excluded_attack_ids": [],
            "reason": "no diff provided; full catalog",
        }

    mapped = families_for_paths(changed_paths)
    if not mapped and default_families:
        mapped = set(default_families)

    selected: list[str] = []
    excluded: list[str] = []
    for aid in attack_ids:
        fam = attack_families.get(aid, "")
        if aid in always or fam in mapped or fam == "composition":
            # composition always optional; include if any parent family maps
            if fam == "composition" and aid not in always:
                # include composition when any surface changed
                if mapped:
                    selected.append(aid)
                else:
                    excluded.append(aid)
            else:
                selected.append(aid)
        else:
            excluded.append(aid)

    if not selected:
        # Fail closed for CI budgets: empty selection is NOT a pass — caller must treat as blocked/skip
        return {
            "mode": "empty_after_diff",
            "changed_paths": changed_paths,
            "mapped_families": sorted(mapped),
            "selected_attack_ids": [],
            "excluded_attack_ids": excluded,
            "reason": "diff mapped to families but no attacks selected",
        }

    return {
        "mode": "diff_filtered",
        "changed_paths": changed_paths,
        "mapped_families": sorted(mapped),
        "selected_attack_ids": selected,
        "excluded_attack_ids": excluded,
        "reason": "filtered by changed trust surfaces",
    }
