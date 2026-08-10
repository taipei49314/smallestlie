"""Diff-aware attack family selection for CI budgets and campaign batch."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from smallestlie.attacks.catalog import AttackCatalog


# Path patterns → attack families (trust-surface map)
_SURFACE_RULES: list[tuple[re.Pattern[str], set[str]]] = [
    (re.compile(r"(^|/)(evidence|artifacts|attestations?)(/|$)", re.I), {"evidence", "freshness"}),
    (re.compile(r"(^|/)(tests?|pytest|junit)(/|$)", re.I), {"execution", "evidence"}),
    (re.compile(r"(^|/)(workflow|\.github|ci)(/|$)", re.I), {"workflow", "projection"}),
    (re.compile(r"(^|/)(policy|gate_policy|config)(/|$)", re.I), {"config", "semantic"}),
    (re.compile(r"(^|/)(authority|approval|actor)(/|$)", re.I), {"authority"}),
    (re.compile(r"(^|/)(protected|identity|path|decoy)(/|$)", re.I), {"path"}),
    (re.compile(r"(^|/)(report|projection|summary|audit-report)(/|$)", re.I), {"projection"}),
    (re.compile(r"(^|/)(verifier|oracle|fixture_gate)(/|$)", re.I), {"verifier", "semantic"}),
    (re.compile(r"(^|/)(revision|REVISION|subject\.json)", re.I), {"freshness", "evidence"}),
    (re.compile(r"(^|/)(semantics\.yaml|status_map)", re.I), {"semantic"}),
    (re.compile(r"(^|/)(matrix\.yaml|execution\.yaml|discovery\.yaml)", re.I), {"execution", "workflow"}),
    (re.compile(r"(^|/)(greenwash)(/|$)", re.I), {"execution", "evidence", "projection", "config"}),
    (re.compile(r"(^|/)(ci-summary|coverage)(/|$)", re.I), {"execution", "projection", "evidence"}),
    (re.compile(r"(^|/)(package/)(.*)", re.I), {"execution", "evidence", "config", "projection"}),
    (re.compile(r"\.(ya?ml|json|xml)$", re.I), set()),  # extension alone — handled below
]

# Filename keywords → families
_NAME_KEYWORDS: list[tuple[re.Pattern[str], set[str]]] = [
    (re.compile(r"approval|authority|approver", re.I), {"authority"}),
    (re.compile(r"evidence|manifest|checksum|hash", re.I), {"evidence"}),
    (re.compile(r"workflow|matrix|job", re.I), {"workflow", "execution"}),
    (re.compile(r"policy|gate", re.I), {"config"}),
    (re.compile(r"semantic|status_map", re.I), {"semantic"}),
    (re.compile(r"protected|identity|path", re.I), {"path"}),
    (re.compile(r"junit|test|pytest", re.I), {"execution"}),
    (re.compile(r"subject|revision|fresh", re.I), {"freshness", "evidence"}),
    (re.compile(r"verify\.py|verifier", re.I), {"verifier"}),
    (re.compile(r"report|projection|summary", re.I), {"projection"}),
]

# Attack-id prefix → family (when catalog family missing)
_ID_PREFIX_FAMILY = {
    "EVD": "evidence",
    "EXE": "execution",
    "SEM": "semantic",
    "PATH": "path",
    "TIME": "freshness",
    "WF": "workflow",
    "AUTH": "authority",
    "CFG": "config",
    "PROJ": "projection",
    "VRF": "verifier",
    "CMP": "composition",
    "GW": None,  # greenwash multi-family — expanded per attack id below
}

_GW_ID_FAMILY = {
    "GW-EXE": "execution",
    "GW-EVD": "evidence",
    "GW-CFG": "config",
    "GW-PATH": "path",
    "GW-PROJ": "projection",
    "GW-SEM": "semantic",
    "GW-AUTH": "authority",
    "GW-TIME": "freshness",
    "GW-WF": "workflow",
}

# Smoke set always kept when diff filters (fail-closed observability)
DEFAULT_ALWAYS_INCLUDE_PREFIXES = ("CFG-001", "EXE-003", "PROJ-005")


def families_for_paths(paths: list[str]) -> dict[str, Any]:
    """Map changed paths to attack families with per-path evidence."""
    families: set[str] = set()
    per_path: dict[str, list[str]] = {}
    for raw in paths:
        p = raw.replace("\\", "/").lstrip("./")
        hit: set[str] = set()
        for pattern, fams in _SURFACE_RULES:
            if fams and pattern.search(p):
                hit |= fams
        base = Path(p).name
        for pattern, fams in _NAME_KEYWORDS:
            if pattern.search(base) or pattern.search(p):
                hit |= fams
        # generic config-like files under fixtures still map config
        if not hit and re.search(r"\.(ya?ml|json)$", p, re.I):
            if "fixture" in p.lower() or "package" in p.lower() or "config" in p.lower():
                hit |= {"config", "semantic"}
        if hit:
            families |= hit
            per_path[p] = sorted(hit)
        else:
            per_path[p] = []
    return {"families": families, "per_path": per_path}


def family_for_attack_id(attack_id: str, declared_family: str | None = None) -> str:
    if declared_family:
        return declared_family
    if attack_id.startswith("GW-"):
        for prefix, fam in _GW_ID_FAMILY.items():
            if attack_id.startswith(prefix):
                return fam or "execution"
    prefix = attack_id.split("-")[0]
    return _ID_PREFIX_FAMILY.get(prefix) or "unknown"


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
    attack_specs: dict[str, dict[str, Any]] | None = None,
    include_smoke: bool = True,
) -> dict[str, Any]:
    """
    Filter attack ids by families implied by changed paths.

    Enhancements:
    - richer path/name rules
    - attack-id prefix family fallback
    - composition included when any parent family maps
    - optional smoke always-include when filtering
    - empty selection remains fail-closed (not a pass)
    """
    always = set(always_include or [])

    if not changed_paths:
        return {
            "mode": "full_catalog",
            "changed_paths": [],
            "mapped_families": sorted(default_families or set(attack_families.values())),
            "selected_attack_ids": list(attack_ids),
            "excluded_attack_ids": [],
            "always_include": sorted(always),
            "path_map": {},
            "reason": "no diff provided; full catalog",
        }

    mapped_info = families_for_paths(changed_paths)
    mapped: set[str] = set(mapped_info["families"])
    # Unknown diff: paths present but none map to a trust surface.
    # Fail closed — do NOT smoke-green unknown paths.
    if not mapped and all(not v for v in (mapped_info.get("per_path") or {}).values()):
        return {
            "mode": "unknown_diff",
            "changed_paths": changed_paths,
            "mapped_families": [],
            "selected_attack_ids": [],
            "excluded_attack_ids": list(attack_ids),
            "always_include": [],
            "path_map": mapped_info["per_path"],
            "reason": "unknown diff paths map to no trust surface; blocked (no smoke fallback)",
        }

    if include_smoke:
        for aid in attack_ids:
            if any(aid.startswith(p) or aid == p for p in DEFAULT_ALWAYS_INCLUDE_PREFIXES):
                always.add(aid)

    if not mapped and default_families:
        mapped = set(default_families)

    specs = attack_specs or {}
    selected: list[str] = []
    excluded: list[str] = []
    reasons: dict[str, str] = {}

    for aid in attack_ids:
        fam = family_for_attack_id(aid, attack_families.get(aid))
        parents = list((specs.get(aid) or {}).get("parents") or [])
        parent_fams = {
            family_for_attack_id(p, attack_families.get(p))
            for p in parents
        }

        if aid in always:
            selected.append(aid)
            reasons[aid] = "always_include"
            continue
        if fam in mapped:
            selected.append(aid)
            reasons[aid] = f"family:{fam}"
            continue
        if fam == "composition" and (parent_fams & mapped or mapped):
            # include compound if any parent family touched, else if any surface changed
            if parent_fams & mapped or not parents:
                selected.append(aid)
                reasons[aid] = f"composition_parents:{sorted(parent_fams & mapped) or 'any'}"
                continue
        excluded.append(aid)
        reasons[aid] = f"excluded_family:{fam}"

    if not selected:
        return {
            "mode": "empty_after_diff",
            "changed_paths": changed_paths,
            "mapped_families": sorted(mapped),
            "selected_attack_ids": [],
            "excluded_attack_ids": excluded,
            "always_include": sorted(always),
            "path_map": mapped_info["per_path"],
            "selection_reasons": reasons,
            "reason": "diff mapped to families but no attacks selected",
        }

    return {
        "mode": "diff_filtered",
        "changed_paths": changed_paths,
        "mapped_families": sorted(mapped),
        "selected_attack_ids": selected,
        "excluded_attack_ids": excluded,
        "always_include": sorted(always),
        "path_map": mapped_info["per_path"],
        "selection_reasons": {k: reasons[k] for k in selected},
        "reason": "filtered by changed trust surfaces (+ smoke always-include)",
    }


def filter_catalog_file(
    path: Path,
    catalog: AttackCatalog,
    selected_ids: list[str],
) -> Path:
    """Write a filtered catalog YAML for a campaign run."""
    path.parent.mkdir(parents=True, exist_ok=True)
    body = {
        "name": f"{catalog.name}-diff-filtered",
        "seed_default": catalog.seed_default,
        "mode": catalog.plan_mode if catalog.plan_mode in {"single", "pairwise", "mixed"} else "single",
        "attacks": selected_ids,
        "limits": catalog.composition_limits,
        "composition_pairs": [list(p) for p in catalog.composition_pairs],
    }
    path.write_text(yaml.safe_dump(body, sort_keys=False), encoding="utf-8")
    return path
