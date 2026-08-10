"""Shared data models for SmallestLie."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class ComparisonResult(str, Enum):
    TRUE_ACCEPT_OBSERVED = "TRUE_ACCEPT_OBSERVED"
    FALSE_REJECT_OBSERVED = "FALSE_REJECT_OBSERVED"
    ATTACK_REJECTED = "ATTACK_REJECTED"
    FALSE_ACCEPT_OBSERVED = "FALSE_ACCEPT_OBSERVED"
    INCONCLUSIVE = "INCONCLUSIVE"
    BLOCKED_BY_POLICY = "BLOCKED_BY_POLICY"
    HARNESS_ERROR = "HARNESS_ERROR"
    INAPPLICABLE = "INAPPLICABLE"
    NOT_RUN = "NOT_RUN"


class CampaignStatus(str, Enum):
    PASS_NO_FALSE_ACCEPT_OBSERVED = "PASS_NO_FALSE_ACCEPT_OBSERVED"
    PASS_WITH_WARNINGS = "PASS_WITH_WARNINGS"
    FAIL_FALSE_ACCEPT_OBSERVED = "FAIL_FALSE_ACCEPT_OBSERVED"
    BLOCKED = "BLOCKED"
    HARNESS_ERROR = "HARNESS_ERROR"


class ExitCode(int, Enum):
    OK_NO_FALSE_ACCEPT = 0
    FALSE_ACCEPT = 2
    INCONCLUSIVE = 3
    BLOCKED = 4
    HARNESS_ERROR = 5
    INVALID_CONFIG = 6


@dataclass
class TargetVerdict:
    accepted: bool
    raw_status: str
    exit_code: int
    report_path: str | None = None
    evidence_refs: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    channels: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class OracleResult:
    valid: bool | None
    reasons: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)
    disagreement: bool = False
    plugins: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Comparison:
    result: ComparisonResult
    oracle_valid: bool | None
    target_accepted: bool | None
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["result"] = self.result.value
        return d


def jsonable(obj: Any) -> Any:
    if isinstance(obj, Enum):
        return obj.value
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    if isinstance(obj, dict):
        return {k: jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [jsonable(v) for v in obj]
    return obj
