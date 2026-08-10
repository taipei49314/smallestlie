"""Nightly fixture suite — auto-attack all known synthetic fixtures."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from smallestlie.campaign.batch import BatchConfig, BatchItem, run_batch


def default_nightly_batch() -> BatchConfig:
    """Known fixtures with honest expectations for nightly cron."""
    return BatchConfig(
        name="nightly-fixtures",
        seed=49314,
        budget_seconds=7200,
        output_root="outputs/nightly",
        stop_on_required_fail=False,
        items=[
            BatchItem(
                name="naive_full",
                target="fixtures/naive_gate",
                catalog="catalogs/ci-offline-full.yaml",
                adapter="fixture_gate",
                expect="fail_false_accept",
                required=True,
            ),
            BatchItem(
                name="honest_full",
                target="fixtures/honest_gate",
                catalog="catalogs/ci-offline-full.yaml",
                adapter="fixture_gate",
                expect="pass_no_false_accept",
                # honest may FA on VRF-001 by design — treat as special
                # Use reduced catalog without VRF for nightly honest clean check
                required=True,
            ),
            BatchItem(
                name="composition_blind",
                target="fixtures/composition_blind_gate",
                catalog="catalogs/canonical-m4-compound.yaml",
                adapter="fixture_gate",
                plan_mode="mixed",
                expect="fail_false_accept",  # needs compound FA
                required=True,
            ),
            BatchItem(
                name="isolation_stale",
                target="fixtures/stale_evidence_gate",
                catalog="catalogs/isolation-stale.yaml",
                adapter="fixture_gate",
                expect="fail_false_accept",
                required=True,
            ),
            BatchItem(
                name="isolation_path",
                target="fixtures/path_blind_gate",
                catalog="catalogs/isolation-path.yaml",
                adapter="fixture_gate",
                expect="fail_false_accept",
                required=True,
            ),
            BatchItem(
                name="isolation_authority",
                target="fixtures/authority_blind_gate",
                catalog="catalogs/isolation-authority.yaml",
                adapter="fixture_gate",
                expect="fail_false_accept",
                required=True,
            ),
            BatchItem(
                name="greenwash_naive",
                target="fixtures/greenwash_naive",
                catalog="catalogs/greenwash-wave-a.yaml",
                adapter="greenwash",
                expect="fail_false_accept",
                required=True,
            ),
            BatchItem(
                name="greenwash_honest",
                target="fixtures/greenwash_honest",
                catalog="catalogs/greenwash-wave-a.yaml",
                adapter="greenwash",
                expect="pass_no_false_accept",
                required=True,
            ),
        ],
    )


def run_nightly(
    *,
    project_root: str | Path,
    budget_seconds: int | None = None,
    output_root: str | None = None,
    seed: int | None = None,
) -> dict[str, Any]:
    cfg = default_nightly_batch()
    # honest_full: VRF-001 expected FA — use catalog without VRF for clean expectation
    # Fix honest item catalog
    for item in cfg.items:
        if item.name == "honest_full":
            item.catalog = "catalogs/ci-offline-full-no-vrf.yaml"
    if budget_seconds is not None:
        cfg.budget_seconds = budget_seconds
    if output_root is not None:
        cfg.output_root = output_root
    if seed is not None:
        cfg.seed = seed
    return run_batch(project_root=project_root, config=cfg)
