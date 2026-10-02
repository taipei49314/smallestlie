"""Prepared slice-C regression; EC admission requires separate authorization."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from workloads.execution_verdict_verify.run import main


if __name__ == "__main__":
    raise SystemExit(main(
        workload_name="m12-adjudication-verify",
        focused_paths=("tests/unit/test_adjudication.py", "tests/unit/test_checkwash_adapter.py",
                       "tests/unit/test_runner_evidence.py", "tests/unit/test_residual_sources.py",
                       "tests/unit/test_execution_verdict.py"),
        heading="SmallestLie M12 research adjudication and finding preservation regression",
    ))
