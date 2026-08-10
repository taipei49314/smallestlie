"""Test surface and module inventory meters."""

from __future__ import annotations

from pathlib import Path

from smallestlie.meters.models import Measurement, MeterVerdict

# Module stems under src/smallestlie we expect some test mention or dedicated file
CRITICAL_MODULES = {
    "policy/path_guard": ["test_path_guard"],
    "policy/authorization": ["test_authorization"],
    "policy/command_allowlist": ["test_command_allowlist"],
    "sandbox/executor": ["test_env_scrubber"],
    "verdict/compare": ["test_comparator"],
    "ledger/verify": ["test_ledger"],
    "attacks/primitives": ["test_mutator"],
    "attacks/composition": ["test_composition"],
    "minimize/ddmin": ["test_ddmin"],
    "ci/status": ["test_ci_status"],
    "ci/diff_select": ["test_diff_select"],
    "campaign/runner": ["test_campaigns", "test_ci_gate", "test_composition_campaign"],
    "oracle/base": ["test_oracles_m2", "test_campaigns"],
}


def measure_test_surface(project_root: Path) -> Measurement:
    tests_root = project_root / "tests"
    test_files = list(tests_root.rglob("test_*.py")) if tests_root.is_dir() else []
    names = {p.stem for p in test_files}
    # also read contents for substring hits
    blobs = []
    for p in test_files:
        try:
            blobs.append(p.read_text(encoding="utf-8"))
        except OSError:
            pass
    joined = "\n".join(blobs)

    covered = []
    gaps = []
    for mod, markers in CRITICAL_MODULES.items():
        hit = any(m in names for m in markers) or any(m in joined for m in markers)
        # also module path string
        if not hit:
            hit = mod.split("/")[-1] in joined
        if hit:
            covered.append(mod)
        else:
            gaps.append(mod)

    ratio = len(covered) / len(CRITICAL_MODULES) if CRITICAL_MODULES else 0.0
    verdict = (
        MeterVerdict.MEASURED_PASS
        if not gaps
        else (MeterVerdict.MEASURED_WARN if ratio >= 0.8 else MeterVerdict.MEASURED_FAIL)
    )
    return Measurement(
        meter_id="inventory.test_surface",
        name="Critical module test surface",
        verdict=verdict,
        value=round(ratio, 4),
        unit="ratio",
        threshold={"min_ratio": 1.0},
        evidence={
            "test_file_count": len(test_files),
            "covered_modules": covered,
            "gap_modules": gaps,
        },
    )


def measure_source_package_layout(project_root: Path) -> Measurement:
    required = [
        "src/smallestlie/cli.py",
        "src/smallestlie/campaign/runner.py",
        "src/smallestlie/oracle/base.py",
        "src/smallestlie/ci/gate.py",
        "pyproject.toml",
        "AUTHORIZED_USE.md",
    ]
    missing = [r for r in required if not (project_root / r).is_file()]
    verdict = MeterVerdict.MEASURED_PASS if not missing else MeterVerdict.MEASURED_FAIL
    return Measurement(
        meter_id="inventory.package_layout",
        name="Core package files present",
        verdict=verdict,
        value=len(required) - len(missing),
        evidence={"missing": missing},
    )
