"""Fixture matrix meters."""

from __future__ import annotations

from pathlib import Path

from smallestlie.meters.models import Measurement, MeterVerdict

EXPECTED_FIXTURES = {
    "naive_gate": {
        "role": "seeded_false_accepts",
        "required_files": ["fixture_gate/verify.py", "REVISION", "gate_policy.yaml"],
    },
    "honest_gate": {
        "role": "reject_invalid",
        "required_files": ["fixture_gate/verify.py", "REVISION", "gate_policy.yaml"],
    },
    "composition_blind_gate": {
        "role": "compound_only_false_accept",
        "required_files": ["fixture_gate/verify.py", "REVISION", "gate_policy.yaml"],
    },
    "stale_evidence_gate": {
        "role": "isolation_freshness",
        "required_files": ["fixture_gate/verify.py", "REVISION", "gate_policy.yaml"],
    },
    "path_blind_gate": {
        "role": "isolation_path",
        "required_files": ["fixture_gate/verify.py", "REVISION", "gate_policy.yaml"],
    },
    "authority_blind_gate": {
        "role": "isolation_authority",
        "required_files": ["fixture_gate/verify.py", "REVISION", "gate_policy.yaml"],
    },
}


def measure_fixture_matrix(project_root: Path) -> Measurement:
    fixtures_root = project_root / "fixtures"
    present = []
    missing = []
    incomplete = []
    for name, meta in EXPECTED_FIXTURES.items():
        d = fixtures_root / name
        if not d.is_dir():
            missing.append(name)
            continue
        absent_files = [f for f in meta["required_files"] if not (d / f).is_file()]
        if absent_files:
            incomplete.append({"fixture": name, "missing_files": absent_files})
        else:
            present.append({"fixture": name, "role": meta["role"]})

    if missing or incomplete:
        verdict = MeterVerdict.MEASURED_FAIL
    else:
        verdict = MeterVerdict.MEASURED_PASS

    return Measurement(
        meter_id="fixture.matrix",
        name="Required synthetic fixture matrix",
        verdict=verdict,
        value=len(present),
        unit="fixtures_ready",
        threshold={"required": list(EXPECTED_FIXTURES)},
        evidence={
            "present": present,
            "missing": missing,
            "incomplete": incomplete,
        },
    )
