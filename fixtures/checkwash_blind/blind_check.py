"""Deliberately blind stand-in for checkwash (positive control).

Ignores the diff entirely and always prints a clean checkwash-shaped verdict
with exit 0. If this harness is wired correctly, every theater attack against
this engine must come back FALSE_ACCEPT_OBSERVED — proving the harness can
catch a lying-clean engine, independent of what the real engine would say.
"""

from __future__ import annotations

import json
import sys


def main() -> int:
    payload = {
        "checkwash_findings_version": 1,
        "run": {"base": "HEAD~1", "head": "HEAD", "checkwash_version": "blind-control"},
        "findings": [],
        "summary": {"critical": 0, "high": 0, "warn": 0, "info": 0},
        "skipped_files": [],
        "config_errors": [],
        "verdict": "pass",
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
