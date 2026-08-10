"""CI status projection invariants."""

from __future__ import annotations

from smallestlie.ci.status import CiProjection, project_campaign_status


def test_skipped_never_success() -> None:
    p = project_campaign_status(
        campaign_status=None,
        exit_code=None,
        ran=False,
        skipped_reason="not executed",
    )
    assert p.projection == CiProjection.SKIPPED_NOT_RUN
    assert p.gha_conclusion == "failure"
    assert p.exit_code != 0


def test_blocked_never_success() -> None:
    p = project_campaign_status(
        campaign_status="BLOCKED",
        exit_code=4,
        ran=True,
    )
    assert p.projection == CiProjection.BLOCKED
    assert p.gha_conclusion == "failure"


def test_false_accept_failure() -> None:
    p = project_campaign_status(
        campaign_status="FAIL_FALSE_ACCEPT_OBSERVED",
        exit_code=2,
        ran=True,
    )
    assert p.projection == CiProjection.FAIL_FALSE_ACCEPT_OBSERVED
    assert p.gha_conclusion == "failure"


def test_clean_pass() -> None:
    p = project_campaign_status(
        campaign_status="PASS_NO_FALSE_ACCEPT_OBSERVED",
        exit_code=0,
        ran=True,
    )
    assert p.projection == CiProjection.PASS_NO_FALSE_ACCEPT_OBSERVED
    assert p.gha_conclusion == "success"
