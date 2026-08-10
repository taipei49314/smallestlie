"""Comparator truth table."""

from __future__ import annotations

from smallestlie.models import ComparisonResult, OracleResult, TargetVerdict
from smallestlie.verdict.compare import compare


def _v(accepted: bool) -> TargetVerdict:
    return TargetVerdict(accepted=accepted, raw_status="X", exit_code=0 if accepted else 1)


def test_false_accept() -> None:
    c = compare(OracleResult(valid=False), _v(True))
    assert c.result == ComparisonResult.FALSE_ACCEPT_OBSERVED


def test_attack_rejected() -> None:
    c = compare(OracleResult(valid=False), _v(False))
    assert c.result == ComparisonResult.ATTACK_REJECTED


def test_true_accept() -> None:
    c = compare(OracleResult(valid=True), _v(True))
    assert c.result == ComparisonResult.TRUE_ACCEPT_OBSERVED


def test_false_reject() -> None:
    c = compare(OracleResult(valid=True), _v(False))
    assert c.result == ComparisonResult.FALSE_REJECT_OBSERVED


def test_inconclusive() -> None:
    c = compare(OracleResult(valid=None), _v(True))
    assert c.result == ComparisonResult.INCONCLUSIVE
