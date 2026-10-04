"""Portable witness regression; separate human EC admission/execution required."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from workloads.execution_verdict_verify.run import main


if __name__ == "__main__":
    raise SystemExit(main(
        workload_name="m12-portable-witness-verify",
        focused_paths=("tests/unit/test_adjudication.py", "tests/unit/test_checkwash_adapter.py",
                       "tests/unit/test_runner_evidence.py", "tests/unit/test_residual_sources.py",
                       "tests/unit/test_execution_verdict.py", "tests/unit/test_multi_dispatch_observations.py",
                       "tests/unit/test_multi_dispatch_reviews.py", "tests/unit/test_multi_dispatch_adjudication.py"),
        heading="SmallestLie M12 portable witness and complete frozen regression",
        focused_timeout=600,
        full_timeout=2400,
    ))
