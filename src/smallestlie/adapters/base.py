"""Adapter interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from smallestlie.models import TargetVerdict
from smallestlie.policy.command_allowlist import CommandAllowlist
from smallestlie.sandbox.executor import ExecutionResult


class EnginePinError(Exception):
    """A pinned external verifier failed its pin/preflight; the run blocks."""


class Adapter(ABC):
    name: str
    version: str

    @abstractmethod
    def command_allowlist(self) -> CommandAllowlist:
        raise NotImplementedError

    @abstractmethod
    def capabilities(self) -> list[str]:
        raise NotImplementedError

    @abstractmethod
    def parse_verdict(
        self,
        workspace: Path,
        execution: ExecutionResult,
    ) -> TargetVerdict:
        raise NotImplementedError

    def preflight(self, workspace: Path) -> dict[str, Any]:
        return {"ok": True}

    def prepare_workspace(self, workspace: Path) -> dict[str, Any]:
        """Hook: called after disposable workspace creation, before mutations.

        Adapters whose verifier needs workspace shape git cannot inherit
        (e.g. a git range for a diff-based SUT) materialize it here.
        Raising blocks the run (BLOCKED_BY_POLICY), never crashes it.
        """
        return {}

    def before_execute(self, workspace: Path) -> dict[str, Any]:
        """Hook: called after mutations are applied, before command execution."""
        return {}


def get_adapter(name: str) -> Adapter:
    from smallestlie.adapters.checkwash import (
        CheckwashAdapter,
        CheckwashBlindAdapter,
    )
    from smallestlie.adapters.fixture_gate import FixtureGateAdapter
    from smallestlie.adapters.greenwash import GreenwashAdapter

    adapters = {
        "fixture_gate": FixtureGateAdapter,
        "greenwash": GreenwashAdapter,
        "checkwash": CheckwashAdapter,
        "checkwash_blind": CheckwashBlindAdapter,
    }
    if name not in adapters:
        raise KeyError(f"unknown adapter: {name}; available={sorted(adapters)}")
    return adapters[name]()
