"""Prepared slice-B regression; EC admission requires separate authorization."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from workloads.execution_verdict_verify.run import main


if __name__ == "__main__":
    raise SystemExit(main(
        workload_name="m12-prereg-evidence-verify",
        focused_paths=("tests/unit/test_preregistration.py", "tests/unit/test_runner_evidence.py",
                       "tests/unit/test_m12_ledger.py", "tests/unit/test_ledger.py",
                       "tests/unit/test_attack_v2_contract.py"),
        heading="SmallestLie M12 preregistration and external evidence regression",
    ))
