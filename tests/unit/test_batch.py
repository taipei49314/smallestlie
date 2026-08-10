"""Batch config loading and small batch run."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from smallestlie.campaign.batch import load_batch_config, run_batch


ROOT = Path(__file__).resolve().parents[2]


def test_load_batch_fixtures_example() -> None:
    cfg = load_batch_config(ROOT / "examples" / "batch.fixtures.yaml")
    assert cfg.name == "fixtures-local"
    assert len(cfg.items) >= 2


@pytest.mark.integration
def test_batch_two_items(tmp_path: Path) -> None:
    cfg_path = tmp_path / "batch.yaml"
    cfg_path.write_text(
        yaml.safe_dump(
            {
                "batch": {
                    "name": "mini",
                    "seed": 49314,
                    "budget_seconds": 600,
                    "output_root": str(tmp_path / "out").replace("\\", "/"),
                    "items": [
                        {
                            "name": "gw_naive",
                            "target": "fixtures/greenwash_naive",
                            "adapter": "greenwash",
                            "catalog": "catalogs/greenwash-wave-a.yaml",
                            "expect": "fail_false_accept",
                            "required": True,
                        },
                        {
                            "name": "gw_honest",
                            "target": "fixtures/greenwash_honest",
                            "adapter": "greenwash",
                            "catalog": "catalogs/greenwash-wave-a.yaml",
                            "expect": "pass_no_false_accept",
                            "required": True,
                        },
                    ],
                }
            }
        ),
        encoding="utf-8",
    )
    cfg = load_batch_config(cfg_path)
    report = run_batch(project_root=ROOT, config=cfg)
    assert report["exit_code"] == 0
    by = {i["name"]: i for i in report["items"]}
    assert by["gw_naive"]["expectation_met"] is True
    assert by["gw_honest"]["expectation_met"] is True
    assert (Path(report["batch_dir"]) / "batch-report.json").is_file()
