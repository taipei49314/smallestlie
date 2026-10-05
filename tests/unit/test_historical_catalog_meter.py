"""Historical preservation cannot turn a stale or damaged catalog into PASS."""

from pathlib import Path
import shutil

import pytest

from smallestlie.attacks.catalog import load_catalog
from smallestlie.meters.catalog_meter import measure_catalog_load

ROOT = Path(__file__).resolve().parents[2]
HISTORY = (
    "catalogs/checkwash-wave-3.yaml",
    "campaigns/checkwash-wave-3/manifest.json",
    "catalogs/residual-rows-checkwash-v0.5.0.json",
    "provenance/checkwash-v0.5.0/SPEC.md",
    "provenance/checkwash-v0.5.0/THREATMODEL.md",
)


def project(root):
    for ref in HISTORY:
        target = root / ref
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / ref, target)
    (root / "attacks/evidence").mkdir(parents=True)
    shutil.copyfile(ROOT / "attacks/evidence/EVD-001.yaml", root / "attacks/evidence/EVD-001.yaml")
    (root / "catalogs/current.yaml").write_text("name: current\nattacks: [EVD-001]\n", encoding="utf-8")
    for source in (ROOT / "attacks/checkwash").glob("CW-W3-*.yaml"):
        shutil.copyfile(source, root / "attacks/evidence" / source.name)
    return root


def test_retained_history_is_visible_and_does_not_pass_current_loader(tmp_path):
    root = project(tmp_path)
    result = measure_catalog_load(root)
    assert result.verdict.value == "MEASURED_WARN"
    assert result.value == 1
    assert result.evidence["loaded"][0]["name"] == "current"
    assert result.evidence["errors"] == []
    assert result.evidence["retained"][0]["verdict"] == "NOT_MEASURED"
    with pytest.raises(ValueError, match="published pin"):
        load_catalog(root / HISTORY[0])


@pytest.mark.parametrize("ref", HISTORY)
def test_changed_historical_input_cannot_hide_current_loader_failure(tmp_path, ref):
    root = project(tmp_path)
    path = root / ref
    path.write_bytes(path.read_bytes() + b"\n")
    result = measure_catalog_load(root)
    assert result.verdict.value == "MEASURED_FAIL"
    assert result.evidence["retained"] == []
    assert result.evidence["errors"]


def test_renamed_old_catalog_and_invalid_current_catalog_are_errors(tmp_path):
    root = project(tmp_path)
    shutil.copyfile(root / HISTORY[0], root / "catalogs/renamed.yaml")
    (root / "catalogs/current.yaml").write_text("schema_version: invalid\n", encoding="utf-8")
    result = measure_catalog_load(root)
    assert result.verdict.value == "MEASURED_FAIL"
    assert {Path(error["path"]).name for error in result.evidence["errors"]} == {"current.yaml", "renamed.yaml"}
    assert result.value == 0
