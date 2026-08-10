"""Blind-spot detector — gaps between claims, meters, catalog, tests, fixtures."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from smallestlie.meters.catalog_meter import DECLARED_FAMILIES, M1_MINIMUM_IDS, discover_all_attacks
from smallestlie.meters.claims_registry import BEHAVIOR_CLAIMS
from smallestlie.meters.models import BlindSpot, Measurement


def find_blindspots(
    project_root: Path,
    measurements: list[Measurement],
    claim_trust: list[dict[str, Any]],
) -> list[BlindSpot]:
    spots: list[BlindSpot] = []
    by_id = {m.meter_id: m for m in measurements}

    # 1) Claims without trust
    for c in claim_trust:
        if c.get("trust_allowed"):
            continue
        if c.get("deferred"):
            spots.append(
                BlindSpot(
                    spot_id=f"claim.deferred.{c['claim_id']}",
                    severity="low",
                    category="deferred_claim",
                    description=f"Behavior claim deferred (meter not run yet): {c['statement']}",
                    remediation=f"Run enabling path for meters {c.get('required_meters')}",
                    evidence={"claim": c},
                )
            )
            continue
        spots.append(
            BlindSpot(
                spot_id=f"claim.untrusted.{c['claim_id']}",
                severity="high" if "FAIL" in c.get("reason", "") else "medium",
                category="untrusted_claim",
                description=f"Behavior claim not trusted: {c['statement']}",
                remediation=f"Satisfy meters {c.get('required_meters')} until PASS; reason={c.get('reason')}",
                evidence={"claim": c},
            )
        )

    # 2) Family taxonomy holes
    attacks = discover_all_attacks(project_root / "attacks")
    families = {a["family"] for a in attacks.values()}
    for fam in sorted(DECLARED_FAMILIES - families):
        sev = "low" if fam == "verifier" else "high"
        spots.append(
            BlindSpot(
                spot_id=f"catalog.family_missing.{fam}",
                severity=sev,
                category="catalog_gap",
                description=f"No attacks in family '{fam}'",
                remediation=f"Add declarative attacks under attacks/* for family {fam}",
                evidence={"family": fam, "backlog": fam == "verifier"},
            )
        )

    # 3) M1 IDs missing
    missing_m1 = sorted(M1_MINIMUM_IDS - set(attacks))
    for mid in missing_m1:
        spots.append(
            BlindSpot(
                spot_id=f"catalog.m1_missing.{mid}",
                severity="high",
                category="catalog_gap",
                description=f"M1 minimum attack missing: {mid}",
                remediation=f"Implement attacks/**/{mid}.yaml",
            )
        )

    # 4) Oracle types never used
    used_oracle_types = set()
    for a in attacks.values():
        if a.get("oracle_type"):
            used_oracle_types.add(a["oracle_type"])
    # plugins inventory vs usage
    oracle_dir = project_root / "src" / "smallestlie" / "oracle"
    plugins = {
        p.stem
        for p in oracle_dir.glob("*.py")
        if p.stem not in {"__init__", "base"}
    } if oracle_dir.is_dir() else set()
    # map plugin file -> rough type names
    plugin_to_types = {
        "discovery": {"required_execution_set"},
        "revision_binding": {"revision_binding"},
        "policy_presence": {"required_policy_presence"},
        "protected_identity": {"protected_identity"},
        "report_exit": {"report_exit_consistency"},
        "artifact_hash": {"artifact_hash_binding"},
        "execution_trace": {"required_execution_set", "matrix_completeness"},
        "workflow": {"workflow_completeness", "matrix_completeness"},
        "authority": {"actor_authority"},
        "semantic_policy": {"semantic_policy", "fail_closed_defaults"},
        "path_canonical": {"path_canonicalization"},
    }
    m_oracle = by_id.get("catalog.oracle_type_usage")
    counts = (m_oracle.evidence or {}).get("counts") if m_oracle else {}
    for plugin, types in plugin_to_types.items():
        if plugin not in plugins:
            continue
        if counts and not any(counts.get(t, 0) > 0 for t in types):
            # also allow composite expansion already in counts
            if not any(t in (counts or {}) for t in types):
                spots.append(
                    BlindSpot(
                        spot_id=f"oracle.unused_plugin.{plugin}",
                        severity="low",
                        category="oracle_gap",
                        description=f"Oracle plugin '{plugin}' may be under-exercised by attack specs",
                        remediation=f"Add attacks with oracle types {sorted(types)} or mark plugin experimental",
                        evidence={"plugin": plugin, "types": sorted(types), "usage": counts},
                    )
                )

    # 5) Fixtures deferred
    fixtures = project_root / "fixtures"
    for name in ("stale_evidence_gate", "path_blind_gate", "authority_blind_gate"):
        if not (fixtures / name).is_dir():
            spots.append(
                BlindSpot(
                    spot_id=f"fixture.missing.{name}",
                    severity="low",
                    category="fixture_gap",
                    description=f"North Star fixture not present: {name}",
                    remediation="Add specialized fixture when isolating that trust surface",
                )
            )

    # 6) CI fast catalog vs full M1
    ci_fast = project_root / "catalogs" / "ci-offline-fast.yaml"
    if ci_fast.is_file():
        import yaml

        raw = yaml.safe_load(ci_fast.read_text(encoding="utf-8")) or {}
        fast_ids = set(raw.get("attacks") or [])
        not_in_ci = sorted(M1_MINIMUM_IDS - fast_ids)
        if not_in_ci:
            spots.append(
                BlindSpot(
                    spot_id="ci.fast_catalog_incomplete_m1",
                    severity="medium",
                    category="ci_gap",
                    description="ci-offline-fast does not cover full M1 minimum set",
                    remediation="Accept as budget tradeoff or expand ci-offline-fast / rely on --full job",
                    evidence={"missing_from_fast": not_in_ci, "fast_ids": sorted(fast_ids)},
                )
            )

    # 7) Meters that are NOT_MEASURED while non-optional claims need them
    for c in BEHAVIOR_CLAIMS:
        optional = bool(c.get("optional_if_not_measured"))
        for mid in c["required_meters"]:
            m = by_id.get(mid)
            if m is None:
                spots.append(
                    BlindSpot(
                        spot_id=f"meter.missing.{mid}",
                        severity="high",
                        category="meter_gap",
                        description=f"Required meter missing from suite: {mid}",
                        remediation="Register meter in measurement suite",
                        evidence={"claim_id": c["claim_id"]},
                    )
                )
            elif m.verdict.value == "NOT_MEASURED" and not optional:
                spots.append(
                    BlindSpot(
                        spot_id=f"meter.not_measured.{mid}",
                        severity="high",
                        category="meter_gap",
                        description=f"Required meter not measured: {mid}",
                        remediation="Run measurement suite path that populates this meter",
                        evidence={"claim_id": c["claim_id"]},
                    )
                )

    # 8) Test surface gaps from meter
    ts = by_id.get("inventory.test_surface")
    if ts and ts.evidence.get("gap_modules"):
        for mod in ts.evidence["gap_modules"]:
            spots.append(
                BlindSpot(
                    spot_id=f"test.gap.{mod.replace('/', '.')}",
                    severity="medium",
                    category="test_gap",
                    description=f"Critical module lacks test surface: {mod}",
                    remediation=f"Add tests covering {mod}",
                )
            )

    # de-dupe by spot_id
    uniq: dict[str, BlindSpot] = {}
    for s in spots:
        uniq[s.spot_id] = s
    # severity sort
    order = {"high": 0, "medium": 1, "low": 2}
    return sorted(uniq.values(), key=lambda s: (order.get(s.severity, 9), s.spot_id))
