"""Resource limits for sandbox execution."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ResourceLimits:
    timeout_seconds: int = 60
    max_output_bytes: int = 1_000_000
    max_files: int = 50_000
    max_workspace_bytes: int = 200_000_000
