"""Attack catalog loader."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from smallestlie.attacks.schema import AttackSchemaError, AttackSpec, V2, load_mapping, parse_attack_spec
from smallestlie.attacks.adjudication import mapping, relative_path, string, strings
from smallestlie.adjudication.residuals import PINNED_INDEX_SHA256, load_residual_catalog


@dataclass
class AttackCatalog:
    name: str
    attack_ids: list[str]
    attacks: dict[str, AttackSpec] = field(default_factory=dict)
    seed_default: int = 49314
    source_path: str | None = None
    plan_mode: str = "single"
    composition_pairs: list[tuple[str, str]] = field(default_factory=list)
    composition_limits: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def ordered(self) -> list[AttackSpec]:
        return [self.attacks[aid] for aid in self.attack_ids if aid in self.attacks]

    def singles(self) -> list[AttackSpec]:
        return [a for a in self.ordered() if a.family != "composition"]

    def compounds(self) -> list[AttackSpec]:
        return [a for a in self.ordered() if a.family == "composition"]


def load_catalog(
    catalog_path: str | Path,
    *,
    attacks_root: str | Path | None = None,
) -> AttackCatalog:
    path = Path(catalog_path)
    raw = load_mapping(path)
    version = raw.get("schema_version", "smallestlie.catalog/v1")
    if not isinstance(version, str) or version not in {"smallestlie.catalog/v1", "smallestlie.catalog/v2"}:
        raise ValueError(f"unsupported catalog schema: {version!r}")
    if version == "smallestlie.catalog/v1" and {"engine", "residual_index"} & raw.keys():
        raise ValueError("v2 catalog metadata cannot be silently interpreted as v1")

    name = str(raw.get("name", path.stem))
    ids = strings(raw.get("attacks") or raw.get("attack_ids") or [], "catalog.attacks")
    if not ids:
        raise ValueError(f"catalog has no attacks: {path}")

    root = Path(attacks_root) if attacks_root else path.parent.parent / "attacks"
    if not root.is_dir():
        root = path.resolve().parent.parent / "attacks"

    found: dict[str, AttackSpec] = {}
    invalid: dict[str, str] = {}
    for yaml_path in sorted(root.rglob("*.yaml")):
        candidate = None
        try:
            candidate = load_mapping(yaml_path)
            spec = parse_attack_spec(candidate, source_path=str(yaml_path))
        except (AttackSchemaError, OSError, TypeError, ValueError) as exc:
            if version == "smallestlie.catalog/v2" and candidate is None:
                raise AttackSchemaError(f"unreadable attack declaration {yaml_path}: {exc}") from exc
            aid = candidate.get("attack_id") if isinstance(candidate, dict) else yaml_path.stem
            if isinstance(aid, str) and aid in ids:
                invalid[aid] = f"{yaml_path}: {exc}"
            continue
        if spec.attack_id in ids:
            if spec.attack_id in found:
                raise ValueError(f"duplicate attack ID {spec.attack_id}: {found[spec.attack_id].source_path}, {yaml_path}")
            found[spec.attack_id] = spec
    if invalid:
        raise AttackSchemaError(f"invalid selected attacks: {invalid}")

    attacks: dict[str, AttackSpec] = {}
    missing: list[str] = []
    for aid in ids:
        if aid not in found:
            missing.append(aid)
            continue
        attacks[aid] = found[aid]
    if missing:
        raise FileNotFoundError(f"catalog attacks not found: {missing}")

    pairs_raw = list(raw.get("composition_pairs") or [])
    pairs: list[tuple[str, str]] = []
    for item in pairs_raw:
        if isinstance(item, (list, tuple)) and len(item) == 2:
            pairs.append((str(item[0]), str(item[1])))

    limits = dict(raw.get("limits") or raw.get("composition_limits") or {})
    mode = str(raw.get("mode", "single"))
    if mode not in {"single", "pairwise", "mixed"}:
        raise ValueError(f"invalid catalog mode: {mode}")

    v2 = [attack for attack in attacks.values() if attack.schema_version == V2]
    metadata = {}
    if version == "smallestlie.catalog/v2" or v2:
        if version != "smallestlie.catalog/v2" or len(v2) != len(attacks):
            raise ValueError("v2 cases require an explicit, unmixed v2 catalog")
        if mode != "single" or pairs_raw or limits:
            raise ValueError("v2 catalogs support only full single-case plans")
        mapping(raw, "v2 catalog", {"schema_version", "name", "attacks", "residual_index", "engine"},
                {"seed_default", "mode"})
        name = string(raw["name"], "catalog.name")
        if type(raw.get("seed_default", 49314)) is not int:
            raise ValueError("catalog.seed_default must be an integer")
        engine = mapping(raw["engine"], "catalog.engine", {"version", "artifact_sha256", "source_revision"})
        index_ref = relative_path(raw["residual_index"], "catalog.residual_index")
        project_root = path.resolve().parent.parent
        index_path = (project_root / index_ref).resolve()
        if not index_path.is_relative_to(project_root):
            raise ValueError("residual index escapes project root")
        from smallestlie.adapters.checkwash import PINNED_SHA256, PINNED_SOURCE_REVISION, PINNED_VERSION
        if (engine["version"] != PINNED_VERSION or engine["artifact_sha256"] != PINNED_SHA256
                or engine["source_revision"] != PINNED_SOURCE_REVISION):
            raise ValueError("v2 catalog engine differs from the published pin")
        index = load_residual_catalog(index_path, expected_engine_version=PINNED_VERSION,
                                     expected_engine_sha256=PINNED_SHA256,
                                     expected_source_revision=engine["source_revision"],
                                     expected_index_sha256=PINNED_INDEX_SHA256,
                                     snapshot_root=project_root)
        rows = index["entries_by_id"]
        for attack in v2:
            adj = attack.adjudication
            assert adj is not None
            for row in adj["residual_mapping"]["row_refs"]:
                if row not in rows:
                    raise ValueError(f"{attack.attack_id}: unknown residual source {row}")
                if (adj["residual_mapping"]["status"] == "matched_residual"
                        and rows[row]["status"] != "documented_residual"):
                    raise ValueError(f"{attack.attack_id}: non-residual row cannot excuse a bypass")
            twin = adj["twin"]
            if twin is not None:
                control = attacks.get(twin["case_id"])
                if control is None:
                    raise ValueError(f"{attack.attack_id}: twin absent from full catalog")
                ctl = control.adjudication
                if (ctl is None or ctl["preregistered_class"] != "CTL"
                        or ctl["control_role"] != twin["role"]
                        or ctl["expected_verifier_outcome"] != "block"
                        or control.runner_protocol != attack.runner_protocol):
                    raise ValueError(f"{attack.attack_id}: twin role/outcome/runner protocol mismatch")
        metadata = {key: raw[key] for key in ("schema_version", "residual_index", "engine")}

    return AttackCatalog(
        name=name,
        attack_ids=ids,
        attacks=attacks,
        seed_default=int(raw.get("seed_default", 49314)),
        source_path=str(path),
        plan_mode=mode,
        composition_pairs=pairs,
        composition_limits=limits,
        metadata=metadata,
    )


def catalog_snapshot(catalog: AttackCatalog) -> dict[str, Any]:
    return {
        **catalog.metadata,
        **({"schema_version": "smallestlie.catalog-snapshot/v1"} if catalog.metadata else {}),
        "name": catalog.name,
        "attack_ids": list(catalog.attack_ids),
        "seed_default": catalog.seed_default,
        "plan_mode": catalog.plan_mode,
        "composition_pairs": [list(p) for p in catalog.composition_pairs],
        "composition_limits": catalog.composition_limits,
        "attacks": {aid: spec.to_dict() for aid, spec in catalog.attacks.items()},
    }
