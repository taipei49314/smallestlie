"""Catalog / attack-family meters."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from smallestlie.adapters.checkwash import PINNED_VERSION
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
    "VRF-001",
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
    if missing:
        verdict = MeterVerdict.MEASURED_FAIL
    else:
        verdict = MeterVerdict.MEASURED_PASS
    return Measurement(
        meter_id="catalog.family_coverage",
        name="Attack family coverage vs North Star taxonomy",
        verdict=verdict,
        value=round(ratio, 4),
        unit="ratio",
        threshold={"missing_must_be_empty": True},
        evidence={
            "present_families": present,
            "missing_families": missing,
            "attack_count": len(attacks),
            "attacks_by_family": _by_family(attacks),
        },
        notes=["MEASURED_PASS means each taxonomy family has ≥1 attack, not product security"],
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


# Exact retained Phase-1 inputs; this registry is not a runtime/approval bypass.
# Changed or renamed files still go through the current loader and fail normally.
_HISTORICAL_W3_INPUTS = {
    "catalogs/checkwash-wave-3.yaml": "ec7326ad7c9f3c5b28b13db7aabf6e4f8b516404f36ffbffe006226123d5ad11",
    "campaigns/checkwash-wave-3/manifest.json": "daf4497f252e141a5d13e2b1e8d461aa590b8089c3006b69703081b24c37c432",
    "catalogs/residual-rows-checkwash-v0.5.0.json": "fc8bab95563fd3b38ae8eb1e6949d38429aecc0ecc4f9625c5d2371344c90bdf",
    "provenance/checkwash-v0.5.0/SPEC.md": "84dbfd719be56c8a8de59c84c6c34160c74d933ea1cda81623790486583c36e3",
    "provenance/checkwash-v0.5.0/THREATMODEL.md": "7ab08e84cec01b9be3e6a683ef17dc68a9fa98b318ef94484ede467aaefe11e9",
}


def _retained_w3(project_root: Path, catalog: Path) -> dict | None:
    if PINNED_VERSION == "0.5.0" or catalog != project_root / "catalogs/checkwash-wave-3.yaml":
        return None
    try:
        for ref, expected in _HISTORICAL_W3_INPUTS.items():
            path = project_root / ref
            if any(part.is_symlink() for part in (path, *path.parents)):
                return None
            if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                return None
    except OSError:
        return None
    return {"path": str(catalog), "verdict": "NOT_MEASURED", "engine_version": "0.5.0",
            "phase1_source_commit": "f673f07110ba6e0b592e6e3ee1e69278ba05e731",
            "manifest_sha256": _HISTORICAL_W3_INPUTS["campaigns/checkwash-wave-3/manifest.json"],
            "reason": "Retained exact historical inputs; current-pin loadability not measured. "
                      "Source lineage does not authenticate approval or execution."}

def measure_catalog_load(project_root: Path) -> Measurement:
    catalogs = list((project_root / "catalogs").glob("*.yaml")) if (project_root / "catalogs").is_dir() else []
    loaded = []
    errors = []
    retained = []
    for c in catalogs:
        historical = _retained_w3(project_root, c)
        if historical is not None:
            retained.append(historical)
            continue
        try:
            cat = load_catalog(c, attacks_root=project_root / "attacks")
            loaded.append({"name": cat.name, "n": len(cat.attack_ids), "mode": cat.plan_mode})
        except Exception as exc:
            errors.append({"path": str(c), "error": str(exc)})
    verdict = MeterVerdict.MEASURED_PASS if loaded and not errors and not retained else (
        MeterVerdict.MEASURED_FAIL if errors else MeterVerdict.MEASURED_WARN
    )
    return Measurement(
        meter_id="catalog.loadable",
        name="Current catalogs load; exact historical inputs remain unmeasured",
        verdict=verdict,
        value=len(loaded),
        unit="catalogs",
        evidence={"loaded": loaded, "errors": errors, "retained": retained},
        notes=["Retained NOT_MEASURED catalogs do not contribute to loaded count or PASS."],
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
