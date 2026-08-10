"""Normalize target verdicts (identity for now; adapter already normalizes)."""

from __future__ import annotations

from smallestlie.models import TargetVerdict


def normalize_verdict(verdict: TargetVerdict) -> TargetVerdict:
    return verdict
