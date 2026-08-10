"""Attack catalog loader."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from smallestlie.attacks.schema import AttackSpec, load_attack_spec


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
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"catalog must be mapping: {path}")

    name = str(raw.get("name", path.stem))
    ids = list(raw.get("attacks") or raw.get("attack_ids") or [])
    if not ids:
        raise ValueError(f"catalog has no attacks: {path}")

    root = Path(attacks_root) if attacks_root else path.parent.parent / "attacks"
    if not root.is_dir():
        root = path.resolve().parent.parent / "attacks"

    found: dict[str, Path] = {}
    for yaml_path in root.rglob("*.yaml"):
        try:
            spec = load_attack_spec(yaml_path)
        except Exception:
            continue
        found[spec.attack_id] = yaml_path

    attacks: dict[str, AttackSpec] = {}
    missing: list[str] = []
    for aid in ids:
        if aid not in found:
            missing.append(aid)
            continue
        attacks[aid] = load_attack_spec(found[aid])
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

    return AttackCatalog(
        name=name,
        attack_ids=ids,
        attacks=attacks,
        seed_default=int(raw.get("seed_default", 49314)),
        source_path=str(path),
        plan_mode=mode,
        composition_pairs=pairs,
        composition_limits=limits,
    )


def catalog_snapshot(catalog: AttackCatalog) -> dict[str, Any]:
    return {
        "name": catalog.name,
        "attack_ids": list(catalog.attack_ids),
        "seed_default": catalog.seed_default,
        "plan_mode": catalog.plan_mode,
        "composition_pairs": [list(p) for p in catalog.composition_pairs],
        "composition_limits": catalog.composition_limits,
        "attacks": {aid: spec.to_dict() for aid, spec in catalog.attacks.items()},
    }
