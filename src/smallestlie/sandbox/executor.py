"""Bounded command executor with scrubbed environment."""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from smallestlie.policy.command_allowlist import CommandAllowlistError, CommandSpec
from smallestlie.policy.network_policy import NetworkPolicy
from smallestlie.policy.path_guard import PathGuard, PathGuardError
from smallestlie.sandbox.limits import ResourceLimits


# Credential-like env keys always stripped.
_CREDENTIAL_KEY_FRAGMENTS = (
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "API_KEY",
    "APIKEY",
    "ACCESS_KEY",
    "PRIVATE_KEY",
    "CREDENTIAL",
    "AUTH_TOKEN",
    "AWS_",
    "AZURE_",
    "GCP_",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "NPM_TOKEN",
    "PYPI_TOKEN",
    "SSH_AUTH_SOCK",
    "SSH_AGENT",
)


@dataclass
class ExecutionResult:
    command_id: str
    argv: list[str]
    cwd: str
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    env_keys: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "command_id": self.command_id,
            "argv": self.argv,
            "cwd": self.cwd,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timed_out": self.timed_out,
            "env_keys": self.env_keys,
        }


def scrub_environment(
    base: dict[str, str] | None = None,
    *,
    extra_allow: set[str] | None = None,
    network_policy: NetworkPolicy | None = None,
) -> dict[str, str]:
    """Build a minimal scrubbed environment for sandbox execution."""
    src = dict(base if base is not None else os.environ)
    allow = {
        "PATH",
        "SYSTEMROOT",
        "SYSTEMDRIVE",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "HOME",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "USERNAME",
        "USER",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "PYTHONIOENCODING",
        "PYTHONUTF8",
        "NUMBER_OF_PROCESSORS",
        "PROCESSOR_ARCHITECTURE",
        "OS",
        # Required for finding the same Python used by harness.
        "VIRTUAL_ENV",
        "UV_PROJECT_ENVIRONMENT",
    }
    if extra_allow:
        allow |= extra_allow

    cleaned: dict[str, str] = {}
    for key, value in src.items():
        upper = key.upper()
        if any(frag in upper for frag in _CREDENTIAL_KEY_FRAGMENTS):
            continue
        if key in allow or upper in {a.upper() for a in allow}:
            cleaned[key] = value

    # Deterministic locale/timezone where practical.
    cleaned.setdefault("LANG", "C")
    cleaned.setdefault("LC_ALL", "C")
    cleaned.setdefault("PYTHONIOENCODING", "utf-8")
    cleaned.setdefault("PYTHONUTF8", "1")
    cleaned["TZ"] = "UTC"
    # Explicitly deny network helpers.
    cleaned["SMALLESTLIE_NETWORK"] = "denied"

    policy = network_policy or NetworkPolicy(mode="denied")
    cleaned = policy.scrub_proxy_env(cleaned)
    return cleaned


class SandboxExecutor:
    def __init__(
        self,
        workspace_root: str | Path,
        *,
        limits: ResourceLimits | None = None,
        network_policy: NetworkPolicy | None = None,
    ) -> None:
        self.guard = PathGuard(workspace_root)
        self.limits = limits or ResourceLimits()
        self.network_policy = network_policy or NetworkPolicy(mode="denied")

    def run(
        self,
        spec: CommandSpec,
        *,
        env: dict[str, str] | None = None,
        extra_env: dict[str, str] | None = None,
    ) -> ExecutionResult:
        self.network_policy.assert_denied()

        cwd_rel = Path(spec.cwd)
        if cwd_rel.is_absolute():
            cwd = self.guard.ensure_inside(cwd_rel, label="command cwd")
        else:
            cwd = self.guard.ensure_relative_inside(cwd_rel)

        argv = list(spec.argv)
        if not argv:
            raise CommandAllowlistError("empty argv")

        # Expand ${PYTHON} placeholder to current interpreter.
        argv = [sys.executable if part == "${PYTHON}" else part for part in argv]

        run_env = scrub_environment(
            env,
            extra_allow=set(spec.env_allowlist),
            network_policy=self.network_policy,
        )
        if extra_env:
            # Only allow non-credential extra keys that were intended.
            for k, v in extra_env.items():
                upper = k.upper()
                if any(frag in upper for frag in _CREDENTIAL_KEY_FRAGMENTS):
                    continue
                run_env[k] = v

        timeout = min(spec.timeout_seconds, self.limits.timeout_seconds)
        try:
            completed = subprocess.run(
                argv,
                cwd=str(cwd),
                env=run_env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
            )
            stdout = completed.stdout or ""
            stderr = completed.stderr or ""
            timed_out = False
            exit_code = int(completed.returncode)
        except subprocess.TimeoutExpired as exc:
            stdout = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
            stderr = (exc.stderr or "") if isinstance(exc.stderr, str) else "timeout"
            timed_out = True
            exit_code = 124
        except FileNotFoundError as exc:
            raise PathGuardError(f"command executable not found: {argv[0]}") from exc

        max_b = self.limits.max_output_bytes
        if len(stdout.encode("utf-8", errors="replace")) > max_b:
            stdout = stdout.encode("utf-8", errors="replace")[:max_b].decode("utf-8", errors="replace")
            stdout += "\n[truncated]"
        if len(stderr.encode("utf-8", errors="replace")) > max_b:
            stderr = stderr.encode("utf-8", errors="replace")[:max_b].decode("utf-8", errors="replace")
            stderr += "\n[truncated]"

        return ExecutionResult(
            command_id=spec.command_id,
            argv=argv,
            cwd=str(cwd),
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            timed_out=timed_out,
            env_keys=sorted(run_env.keys()),
        )
