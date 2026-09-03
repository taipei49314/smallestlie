"""The vendored checkwash engine, its constants and its ledger row move together.

estate-consolidation T-57 D-4 (2026-09-03): checkwash is re-pinned only in the
cadence PR that follows a checkwash release slot. Between slots nothing here may
drift: the constants in ``adapters/checkwash.py``, the table in
``verifiers/README.md`` and the artifact itself must describe the same
*released* version. These tests do not need the network; they cannot prove the
tag exists on GitHub, only that every local record agrees and that the number
has the shape of a release, not a dev build.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

from smallestlie.adapters.checkwash import PINNED_SHA256, PINNED_VERSION, verify_engine_pin

ROOT = Path(__file__).resolve().parents[2]
RELEASE_VERSION = re.compile(r"^\d+\.\d+\.\d+$")


def test_pinned_version_is_a_release_number() -> None:
    assert RELEASE_VERSION.match(PINNED_VERSION), (
        f"PINNED_VERSION {PINNED_VERSION!r} is not a released X.Y.Z; only release "
        "assets are pinned (T-57 D-4)"
    )


def test_ledger_row_matches_constants() -> None:
    table = (ROOT / "verifiers" / "README.md").read_text(encoding="utf-8")
    version = re.search(r"^\| Version \| v(\d+\.\d+\.\d+) \|", table, re.M)
    digest = re.search(r"^\| SHA-256 \| `([0-9a-f]{64})` \|", table, re.M)
    assert version is not None and version.group(1) == PINNED_VERSION, (
        "verifiers/README.md Version row drifted from PINNED_VERSION"
    )
    assert digest is not None and digest.group(1) == PINNED_SHA256, (
        "verifiers/README.md SHA-256 row drifted from PINNED_SHA256"
    )
    assert f"annotated tag `v{PINNED_VERSION}`" in table, (
        "verifiers/README.md must name the annotated release tag the artifact came from"
    )


def test_vendored_engine_reports_the_pinned_version() -> None:
    path = verify_engine_pin()
    out = subprocess.run(
        [sys.executable, str(path), "--version"],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    assert out.stdout.strip() == f"checkwash {PINNED_VERSION}", out.stdout
