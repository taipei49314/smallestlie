"""Raw command capture for a separately authenticated formal collector.

This API records bytes and command-process facts. It does not authenticate a
run, assert process-tree isolation, or mint an execution/verifier envelope.
Legacy SandboxExecutor.run() and its text/exit contract are unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

from smallestlie.campaign.preregistration import canonical_digest, digest
from smallestlie.policy.command_allowlist import CommandAllowlistError, CommandSpec
from smallestlie.sandbox.executor import SandboxExecutor, scrub_environment


@dataclass(frozen=True)
class ByteCapture:
    command_id: str
    argv: tuple[str, ...]
    cwd: str
    environment: tuple[tuple[str, str], ...]
    termination_kind: str
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    stdout_total_bytes: int | None
    stderr_total_bytes: int | None
    stdout_truncated: bool
    stderr_truncated: bool
    diagnostic: str | None = None

    def metadata(self) -> dict:
        # Environment values remain available to the trusted collector, not
        # copied into a public report. Bytes are stored as separate artifacts.
        return {"schema_version": "smallestlie.raw-command-capture/v1",
                "command_id": self.command_id, "argv": list(self.argv), "cwd": self.cwd,
                "environment_sha256": canonical_digest(self.environment),
                "supervisor_scope": "command-process", "stream_scope": "post-command-snapshot",
                "termination_kind": self.termination_kind,
                "exit_code": self.exit_code, "diagnostic": self.diagnostic,
                "stdout": {"sha256": digest(self.stdout), "captured_bytes": len(self.stdout),
                           "observed_bytes": self.stdout_total_bytes, "truncated": self.stdout_truncated},
                "stderr": {"sha256": digest(self.stderr), "captured_bytes": len(self.stderr),
                           "observed_bytes": self.stderr_total_bytes, "truncated": self.stderr_truncated}}


def _snapshot(writer, maximum: int) -> tuple[bytes, int, bool]:
    # Reopen independently: dup/seek on the writer's file description would
    # change a surviving descendant's offset on POSIX. On Windows both opens
    # share delete access so the temporary file can outlive our handles safely.
    original = os.fstat(writer.fileno())
    flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_NONBLOCK", 0))
    if os.name == "nt":
        flags |= os.O_TEMPORARY
    with os.fdopen(os.open(writer.name, flags), "rb") as reader:
        actual = os.fstat(reader.fileno())
        if (not original.st_ino or not stat.S_ISREG(actual.st_mode)
                or not os.path.samestat(original, actual)):
            raise OSError("raw capture stream identity changed")
        total = original.st_size
        expected = min(total, maximum)
        data = reader.read(expected)
        return data, total, total > maximum or len(data) != expected


class ByteCaptureExecutor(SandboxExecutor):
    def run_bytes(self, spec: CommandSpec, *, env: dict[str, str] | None = None,
                  extra_env: dict[str, str] | None = None) -> ByteCapture:
        self.network_policy.assert_denied()
        cwd_rel = Path(spec.cwd)
        cwd = (self.guard.ensure_inside(cwd_rel, label="command cwd") if cwd_rel.is_absolute()
               else self.guard.ensure_relative_inside(cwd_rel))
        if not spec.argv:
            raise CommandAllowlistError("empty argv")
        argv = tuple(sys.executable if part == "${PYTHON}" else part for part in spec.argv)
        maximum = self.limits.max_output_bytes
        if any(type(value) is not int or value < 1 for value in
               (spec.timeout_seconds, self.limits.timeout_seconds, maximum)):
            raise CommandAllowlistError("raw capture requires positive integer time/output limits")
        timeout = min(spec.timeout_seconds, self.limits.timeout_seconds)
        key_name = str.upper if os.name == "nt" else lambda value: value
        combined = {key_name(key): value for key, value in (env if env is not None else os.environ).items()}
        combined.update({key_name(key): value for key, value in (extra_env or {}).items()})
        run_env = scrub_environment(combined,
            extra_allow=set(spec.env_allowlist) | set(extra_env or {}), network_policy=self.network_policy)

        process = None
        kind, code, diagnostic = "spawn_error", None, None
        # File redirection preserves invalid UTF-8 and CRLF, and avoids waiting
        # on inherited stdout/stderr pipes after command-process termination.
        # The outer trusted collector owns descendant cleanup and storage quotas.
        with tempfile.NamedTemporaryFile("w+b") as stdout_file, tempfile.NamedTemporaryFile("w+b") as stderr_file:
            try:
                process = subprocess.Popen(argv, cwd=str(cwd), env=run_env,
                    stdin=subprocess.DEVNULL, stdout=stdout_file, stderr=stderr_file,
                    close_fds=True, shell=False)
                try:
                    code = process.wait(timeout=timeout)
                    kind = "signal" if os.name != "nt" and code < 0 else "completed"
                except subprocess.TimeoutExpired:
                    kind = "timeout"
                    process.kill()
                    code = process.wait(timeout=1)
            except (OSError, subprocess.SubprocessError) as exc:
                diagnostic = type(exc).__name__
                kind = "spawn_error" if process is None else "internal_error"
                if process is not None:
                    try:
                        if process.poll() is None:
                            process.kill()
                        code = process.wait(timeout=1)
                    except (OSError, subprocess.SubprocessError):
                        code = None
            try:
                captures = [_snapshot(stream, maximum) for stream in (stdout_file, stderr_file)]
            except OSError as exc:
                kind, diagnostic = "internal_error", type(exc).__name__
                # No substituted bytes or invented lengths become evidence.
                captures = [(b"", None, True), (b"", None, True)]
        out, err = captures
        return ByteCapture(spec.command_id, argv, str(cwd), tuple(sorted(run_env.items())), kind, code,
                           out[0], err[0], out[1], err[1], out[2], err[2], diagnostic)
