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
    # A verifier's ordinary rejection is a completed execution, not a crash.
    verdict_exit_codes: tuple[int, ...] = (0, 1)

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

    def read_verdict(
        self,
        workspace: Path,
        execution: ExecutionResult,
    ) -> TargetVerdict:
        """Require a completed execution before interpreting target output.

        Campaigns, minimization and replay share this boundary. Partial or stale
        output from a timeout/crash cannot become either a defense or a witness.
        """
        error = None
        if execution.timed_out:
            error = "timed_out"
        elif execution.exit_code not in self.verdict_exit_codes:
            error = f"unexpected_exit_code:{execution.exit_code}"
        if error is not None:
            return TargetVerdict(
                accepted=False,
                raw_status="EXECUTION_INCOMPLETE",
                exit_code=execution.exit_code,
                execution_error=error,
                channels={
                    "exit_code": execution.exit_code,
                    "timed_out": execution.timed_out,
                    "stdout_tail": (execution.stdout or "")[-500:],
                    "stderr_tail": (execution.stderr or "")[-500:],
                },
            )
        return self.parse_verdict(workspace, execution)

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
