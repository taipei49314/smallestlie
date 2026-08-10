"""Catalog / attack-family meters."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from smallestlie.attacks.catalog import load_catalog
from smallestlie.attacks.schema import load_attack_spec
from smallestlie.meters.models import Measurement, MeterVerdict

# North Star families (core trust surfaces)
DECLARED_FAMILIES = {
    "evidence",
    "execution",
    "semantic",
    "path",
    "freshness",
    "workflow",
    "authority",
    "composition",
    "config",
    "verifier",
    "projection",
}

# M1 minimum set from North Star §20 M1
M1_MINIMUM_IDS = {
    "EVD-001",
    "EVD-002",
    "EVD-003",
    "EXE-001",
    "EXE-002",
    "EXE-003",
    "SEM-001",
    "SEM-003",
    "PATH-001",
    "PATH-002",
    "TIME-001",
    "WF-001",
    "AUTH-001",
    "CFG-001",
    "PROJ-005",
}


def discover_all_attacks(attacks_root: Path) -> dict[str, dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    if not attacks_root.is_dir():
        return found
    for p in attacks_root.rglob("*.yaml"):
        try:
            spec = load_attack_spec(p)
        except Exception:
            continue
        found[spec.attack_id] = {
            "attack_id": spec.attack_id,
            "family": spec.family,
            "path": str(p),
            "oracle_type": (spec.oracle or {}).get("type"),
            "mutation_count": len(spec.mutations or []),
        }
    return found


def measure_family_coverage(project_root: Path) -> Measurement:
    attacks = discover_all_attacks(project_root / "attacks")
    families_present = {a["family"] for a in attacks.values()}
    missing = sorted(DECLARED_FAMILIES - families_present)
    present = sorted(families_present & DECLARED_FAMILIES)
    ratio = len(present) / len(DECLARED_FAMILIES) if DECLARED_FAMILIES else 0.0
    # verifier may be empty intentionally at M1-M5 — warn not fail if only verifier missing
    # Pre-VRF milestone: missing `verifier` family is an explicit backlog blind spot,
    # not a failed measurement of the current declared M1–M5 surface.
    soft_allow = {"verifier"}
    hard_missing = [f for f in missing if f not in soft_allow]
    soft_missing = [f for f in missing if f in soft_allow]
    if hard_missing:
        verdict = MeterVerdict.MEASURED_FAIL
    else:
        verdict = MeterVerdict.MEASURED_PASS
    return Measurement(
        meter_id="catalog.family_coverage",
        name="Attack family coverage vs North Star taxonomy",
        verdict=verdict,
        value=round(ratio, 4),
        unit="ratio",
        threshold={"hard_missing_must_be_empty": True, "soft_allow": sorted(soft_allow)},
        evidence={
            "present_families": present,
            "missing_families": missing,
            "hard_missing": hard_missing,
            "soft_missing": soft_missing,
            "attack_count": len(attacks),
            "attacks_by_family": _by_family(attacks),
        },
        notes=[
            "soft_missing families remain as blind-spot backlog items",
            "MEASURED_PASS here does not mean full North Star taxonomy is complete",
        ],
    )


def measure_m1_presence(project_root: Path) -> Measurement:
    attacks = discover_all_attacks(project_root / "attacks")
    ids = set(attacks)
    missing = sorted(M1_MINIMUM_IDS - ids)
    extra_compounds = sorted(i for i in ids if i.startswith("CMP-"))
    verdict = MeterVerdict.MEASURED_PASS if not missing else MeterVerdict.MEASURED_FAIL
    return Measurement(
        meter_id="catalog.m1_minimum",
        name="M1 minimum attack ID presence",
        verdict=verdict,
        value=len(M1_MINIMUM_IDS) - len(missing),
        unit="count",
        threshold={"required": sorted(M1_MINIMUM_IDS)},
        evidence={
            "missing_ids": missing,
            "present_count": len(M1_MINIMUM_IDS) - len(missing),
            "compound_ids": extra_compounds,
        },
    )


def measure_composition_presence(project_root: Path) -> Measurement:
    attacks = discover_all_attacks(project_root / "attacks")
    compounds = [a for a in attacks.values() if a["family"] == "composition"]
    verdict = (
        MeterVerdict.MEASURED_PASS if len(compounds) >= 1 else MeterVerdict.MEASURED_FAIL
    )
    return Measurement(
        meter_id="catalog.composition_presence",
        name="Composition attack corpus present",
        verdict=verdict,
        value=len(compounds),
        unit="count",
        threshold={"min": 1},
        evidence={"compound_ids": [c["attack_id"] for c in compounds]},
    )


def measure_catalog_load(project_root: Path) -> Measurement:
    catalogs = list((project_root / "catalogs").glob("*.yaml")) if (project_root / "catalogs").is_dir() else []
    loaded = []
    errors = []
    for c in catalogs:
        try:
            cat = load_catalog(c, attacks_root=project_root / "attacks")
            loaded.append({"name": cat.name, "n": len(cat.attack_ids), "mode": cat.plan_mode})
        except Exception as exc:
            errors.append({"path": str(c), "error": str(exc)})
    verdict = MeterVerdict.MEASURED_PASS if loaded and not errors else (
        MeterVerdict.MEASURED_FAIL if errors else MeterVerdict.MEASURED_WARN
    )
    return Measurement(
        meter_id="catalog.loadable",
        name="All catalog YAML files load",
        verdict=verdict,
        value=len(loaded),
        unit="catalogs",
        evidence={"loaded": loaded, "errors": errors},
    )


def measure_incompleteness_hooks(project_root: Path) -> Measurement:
    """Static: models expose incompleteness result tokens."""
    from smallestlie.models import CampaignStatus, ComparisonResult

    needed = {
        "INCONCLUSIVE",
        "INAPPLICABLE",
        "BLOCKED_BY_POLICY",
        "HARNESS_ERROR",
        "NOT_RUN",
    }
    have = {e.value for e in ComparisonResult}
    # campaign statuses
    camp = {e.value for e in CampaignStatus}
    missing = sorted(needed - have)
    # BLOCKED is campaign-level
    if "BLOCKED" not in camp:
        missing.append("CampaignStatus.BLOCKED")
    verdict = MeterVerdict.MEASURED_PASS if not missing else MeterVerdict.MEASURED_FAIL
    return Measurement(
        meter_id="catalog.incompleteness_hooks",
        name="Incompleteness result tokens exist in models",
        verdict=verdict,
        value=len(needed - set(missing)),
        evidence={"comparison_results": sorted(have), "campaign_statuses": sorted(camp), "missing": missing},
    )


def measure_oracle_types_used(project_root: Path) -> Measurement:
    attacks = discover_all_attacks(project_root / "attacks")
    types: dict[str, int] = {}
    for a in attacks.values():
        t = a.get("oracle_type") or "unknown"
        if t == "composite":
            # expand plugins from file
            try:
                spec = load_attack_spec(a["path"])
                plugins = (spec.oracle or {}).get("plugins") or []
                if not plugins:
                    types["composite"] = types.get("composite", 0) + 1
                for p in plugins:
                    pt = p.get("type", "unknown")
                    types[pt] = types.get(pt, 0) + 1
            except Exception:
                types["composite"] = types.get("composite", 0) + 1
        else:
            types[t] = types.get(t, 0) + 1
    return Measurement(
        meter_id="catalog.oracle_type_usage",
        name="Oracle types referenced by attacks",
        verdict=MeterVerdict.MEASURED_PASS if types else MeterVerdict.MEASURED_FAIL,
        value=len(types),
        unit="distinct_oracle_types",
        evidence={"counts": dict(sorted(types.items()))},
    )


def _by_family(attacks: dict[str, dict[str, Any]]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for a in attacks.values():
        out.setdefault(a["family"], []).append(a["attack_id"])
    for k in out:
        out[k] = sorted(out[k])
    return out
