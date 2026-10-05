"""One fixed Windows regression partition; new declaration admission is required.

SOURCE_ONLY / NOT_RUN until remote CI and separately accounted pool execution.
"""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from workloads.m12_adjudication_verify.partitioned import main


if __name__ == "__main__":
    raise SystemExit(main())
