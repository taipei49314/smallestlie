"""Adapter interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from smallestlie.models import TargetVerdict
from smallestlie.policy.command_allowlist import CommandAllowlist
from smallestlie.sandbox.executor import ExecutionResult


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


def get_adapter(name: str) -> Adapter:
    from smallestlie.adapters.fixture_gate import FixtureGateAdapter

    adapters = {
        "fixture_gate": FixtureGateAdapter,
    }
    if name not in adapters:
        raise KeyError(f"unknown adapter: {name}; available={sorted(adapters)}")
    return adapters[name]()
