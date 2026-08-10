"""Comparator truth table."""

from __future__ import annotations

from smallestlie.models import Comparison, ComparisonResult, OracleResult, TargetVerdict


def compare(oracle: OracleResult, target: TargetVerdict | None) -> Comparison:
    if oracle.valid is None:
        return Comparison(
            result=ComparisonResult.INCONCLUSIVE,
            oracle_valid=None,
            target_accepted=target.accepted if target else None,
            rationale="oracle validity unknown / plugin disagreement",
        )
    if target is None:
        return Comparison(
            result=ComparisonResult.HARNESS_ERROR,
            oracle_valid=oracle.valid,
            target_accepted=None,
            rationale="missing target verdict",
        )

    if oracle.valid and target.accepted:
        return Comparison(
            result=ComparisonResult.TRUE_ACCEPT_OBSERVED,
            oracle_valid=True,
            target_accepted=True,
            rationale="oracle valid and target accepted",
        )
    if oracle.valid and not target.accepted:
        return Comparison(
            result=ComparisonResult.FALSE_REJECT_OBSERVED,
            oracle_valid=True,
            target_accepted=False,
            rationale="oracle valid but target rejected",
        )
    if (not oracle.valid) and (not target.accepted):
        return Comparison(
            result=ComparisonResult.ATTACK_REJECTED,
            oracle_valid=False,
            target_accepted=False,
            rationale="oracle invalid and target rejected (defense observed)",
        )
    # not oracle.valid and target.accepted
    return Comparison(
        result=ComparisonResult.FALSE_ACCEPT_OBSERVED,
        oracle_valid=False,
        target_accepted=True,
        rationale="oracle invalid but target accepted — false acceptance",
    )
