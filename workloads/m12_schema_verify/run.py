"""Prepared M12 slice-A verification; EC admission requires separate approval."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from workloads.execution_verdict_verify.run import main


if __name__ == "__main__":
    raise SystemExit(main(
        workload_name="m12-schema-v2-verify",
        focused_paths=("tests/unit/test_attack_v2_contract.py",
                       "tests/unit/test_residual_sources.py",
                       "tests/unit/test_composition.py",
                       "tests/unit/test_diff_select.py",
                       "tests/unit/test_checkwash_wave1_catalog.py"),
        heading="SmallestLie M12 schema and pinned-source regression",
    ))
