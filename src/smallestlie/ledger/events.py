"""Ledger event types."""

from __future__ import annotations

from typing import Final

EVENT_CAMPAIGN_CREATED: Final = "campaign_created"
EVENT_POLICY_VALIDATED: Final = "policy_validated"
EVENT_BASELINE_CAPTURED: Final = "baseline_captured"
EVENT_MUTANT_CREATED: Final = "mutant_created"
EVENT_MUTATION_APPLIED: Final = "mutation_applied"
EVENT_COMMAND_EXECUTED: Final = "command_executed"
EVENT_ORACLE_EVALUATED: Final = "oracle_evaluated"
EVENT_TARGET_VERDICT_PARSED: Final = "target_verdict_parsed"
EVENT_COMPARATOR_RESULT: Final = "comparator_result"
EVENT_MINIMIZATION: Final = "minimization"
EVENT_REPLAY_RESULT: Final = "replay_result"
EVENT_REGRESSION_EXPORT: Final = "regression_export"
EVENT_CAMPAIGN_SUMMARY: Final = "campaign_summary"
EVENT_BLOCKED: Final = "blocked"
EVENT_HARNESS_ERROR: Final = "harness_error"
