"""Meter result models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class MeterVerdict(str, Enum):
    """Meter outcomes — never use SECURE."""

    MEASURED_PASS = "MEASURED_PASS"  # threshold met with evidence
    MEASURED_FAIL = "MEASURED_FAIL"  # measured and failed threshold
    MEASURED_WARN = "MEASURED_WARN"  # measured, incomplete or soft fail
    NOT_MEASURED = "NOT_MEASURED"  # no instrument ran
    BLOCKED = "BLOCKED"  # could not measure


@dataclass
class Measurement:
    meter_id: str
    name: str
    verdict: MeterVerdict
    value: Any = None
    unit: str = ""
    threshold: Any = None
    evidence: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["verdict"] = self.verdict.value
        return d


@dataclass
class BlindSpot:
    spot_id: str
    severity: str  # high | medium | low
    category: str
    description: str
    remediation: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ClaimRecord:
    """A behavior claim that must not be trusted without a meter."""

    claim_id: str
    statement: str
    required_meters: list[str]
    trust_allowed: bool
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
