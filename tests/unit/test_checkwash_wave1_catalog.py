"""Wave1 catalog loads every frozen attack id."""

from __future__ import annotations

from pathlib import Path

from smallestlie.attacks.catalog import load_catalog

ROOT = Path(__file__).resolve().parents[2]
WAVE1_IDS = [
    "CW-W1-54",
    "CW-W1-77",
    "CW-W1-86a",
    "CW-W1-93",
    "CW-W1-2HOP",
    "CW-W1-91H",
    "CW-W1-TWIN",
]


def test_wave1_catalog_resolves_all_ids() -> None:
    catalog = load_catalog(ROOT / "catalogs" / "checkwash-wave1.yaml")
    assert catalog.attack_ids == WAVE1_IDS
    assert list(catalog.attacks) == WAVE1_IDS
    for aid in WAVE1_IDS:
        spec = catalog.attacks[aid]
        assert spec.attack_id == aid
        assert spec.mutations
        assert spec.execute.get("command_ref") == "run_checkwash_check"
