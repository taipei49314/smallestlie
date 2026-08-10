"""Command allowlist tests."""

from __future__ import annotations

import pytest

from smallestlie.policy.command_allowlist import CommandAllowlist, CommandAllowlistError


def test_resolve_known_command() -> None:
    al = CommandAllowlist.from_mapping(
        {"run_target_verifier": {"argv": ["python", "-m", "fixture_gate", "verify"]}}
    )
    spec = al.resolve("run_target_verifier")
    assert spec.argv[0] == "python"


def test_unapproved_command_blocked() -> None:
    al = CommandAllowlist.from_mapping(
        {"run_target_verifier": {"argv": ["python", "-m", "fixture_gate", "verify"]}}
    )
    with pytest.raises(CommandAllowlistError, match="not on allowlist"):
        al.resolve("rm_rf_everything")


def test_shell_metacharacters_rejected() -> None:
    with pytest.raises(CommandAllowlistError, match="metacharacters"):
        CommandAllowlist.from_mapping(
            {"bad": {"argv": ["python", "-c", "print(1); import os"]}}
        )
