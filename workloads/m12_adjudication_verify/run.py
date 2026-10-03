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
        # PR34's full suite used 1082.641 of 1200 seconds. Keep the complete
        # denominator and the EC outer 35-minute bound; allow this new slice
        # 1600 seconds internally. Other workloads retain the default 1200.
        full_timeout=1600,
    ))
