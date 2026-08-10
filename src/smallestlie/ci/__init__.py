"""CI / release-gate integration (M5)."""

from smallestlie.ci.gate import run_ci_gate
from smallestlie.ci.summary import write_ci_summary

__all__ = ["run_ci_gate", "write_ci_summary"]
