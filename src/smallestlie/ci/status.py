"""Explicit CI status projection — never collapse skip/block into pass."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class CiProjection(str, Enum):
    """Statuses safe to surface in CI badges / job conclusions."""

    PASS_NO_FALSE_ACCEPT_OBSERVED = "PASS_NO_FALSE_ACCEPT_OBSERVED"
    FAIL_FALSE_ACCEPT_OBSERVED = "FAIL_FALSE_ACCEPT_OBSERVED"
    PASS_WITH_WARNINGS = "PASS_WITH_WARNINGS"
    BLOCKED = "BLOCKED"
    HARNESS_ERROR = "HARNESS_ERROR"
    SKIPPED_NOT_RUN = "SKIPPED_NOT_RUN"
    INVALID_CONFIG = "INVALID_CONFIG"


# GitHub Actions job conclusions (subset)
GHA_CONCLUSION = {
    CiProjection.PASS_NO_FALSE_ACCEPT_OBSERVED: "success",
    CiProjection.PASS_WITH_WARNINGS: "success",  # success with annotations
    CiProjection.FAIL_FALSE_ACCEPT_OBSERVED: "failure",
    CiProjection.BLOCKED: "failure",  # never green when blocked
    CiProjection.HARNESS_ERROR: "failure",
    CiProjection.SKIPPED_NOT_RUN: "failure",  # skipped must NOT be success
    CiProjection.INVALID_CONFIG: "failure",
}


@dataclass
class ProjectedStatus:
    projection: CiProjection
    exit_code: int
    gha_conclusion: str
    badge_label: str
    notes: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "projection": self.projection.value,
            "exit_code": self.exit_code,
            "gha_conclusion": self.gha_conclusion,
            "badge_label": self.badge_label,
            "notes": self.notes,
        }


def project_campaign_status(
    *,
    campaign_status: str | None,
    exit_code: int | None,
    ran: bool,
    skipped_reason: str | None = None,
    budget_exceeded: bool = False,
) -> ProjectedStatus:
    """
    Map campaign outcome to CI-facing projection.

    Invariant: SKIPPED_NOT_RUN and BLOCKED never become success.
    """
    notes: list[str] = []
    if not ran:
        notes.append(skipped_reason or "campaign not executed")
        return ProjectedStatus(
            projection=CiProjection.SKIPPED_NOT_RUN,
            exit_code=4,
            gha_conclusion=GHA_CONCLUSION[CiProjection.SKIPPED_NOT_RUN],
            badge_label="not-run",
            notes=notes,
        )

    if budget_exceeded:
        notes.append("runtime budget exceeded")

    status = (campaign_status or "").upper()
    code = int(exit_code if exit_code is not None else 5)

    if status == "FAIL_FALSE_ACCEPT_OBSERVED" or code == 2:
        proj = CiProjection.FAIL_FALSE_ACCEPT_OBSERVED
        code = 2
    elif status == "BLOCKED" or code == 4:
        proj = CiProjection.BLOCKED
        code = 4
    elif status == "HARNESS_ERROR" or code == 5:
        proj = CiProjection.HARNESS_ERROR
        code = 5
    elif status == "PASS_WITH_WARNINGS" or code == 3:
        proj = CiProjection.PASS_WITH_WARNINGS
        code = 3 if not budget_exceeded else 3
        if budget_exceeded:
            # Budget exceeded must not be a clean pass.
            notes.append("budget exceeded elevates warning")
    elif status == "PASS_NO_FALSE_ACCEPT_OBSERVED" or code == 0:
        if budget_exceeded:
            proj = CiProjection.PASS_WITH_WARNINGS
            code = 3
        else:
            proj = CiProjection.PASS_NO_FALSE_ACCEPT_OBSERVED
            code = 0
    else:
        proj = CiProjection.HARNESS_ERROR
        code = 5
        notes.append(f"unrecognized campaign status: {campaign_status!r}")

    badge = {
        CiProjection.PASS_NO_FALSE_ACCEPT_OBSERVED: "no-false-accept",
        CiProjection.PASS_WITH_WARNINGS: "warnings",
        CiProjection.FAIL_FALSE_ACCEPT_OBSERVED: "false-accept",
        CiProjection.BLOCKED: "blocked",
        CiProjection.HARNESS_ERROR: "harness-error",
        CiProjection.SKIPPED_NOT_RUN: "not-run",
        CiProjection.INVALID_CONFIG: "invalid-config",
    }[proj]

    return ProjectedStatus(
        projection=proj,
        exit_code=code,
        gha_conclusion=GHA_CONCLUSION[proj],
        badge_label=badge,
        notes=notes,
    )
