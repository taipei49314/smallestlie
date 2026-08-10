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

    def ordered(self) -> list[AttackSpec]:
        return [self.attacks[aid] for aid in self.attack_ids if aid in self.attacks]


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
        # Fallback: sibling attacks/ relative to CWD layout.
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

    return AttackCatalog(
        name=name,
        attack_ids=ids,
        attacks=attacks,
        seed_default=int(raw.get("seed_default", 49314)),
        source_path=str(path),
    )


def catalog_snapshot(catalog: AttackCatalog) -> dict[str, Any]:
    return {
        "name": catalog.name,
        "attack_ids": list(catalog.attack_ids),
        "seed_default": catalog.seed_default,
        "attacks": {aid: spec.to_dict() for aid, spec in catalog.attacks.items()},
    }
