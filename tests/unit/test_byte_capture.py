"""Tiny command probes run only by the separately authorized pool regression."""

import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace

import pytest

from smallestlie.campaign.preregistration import canonical_digest, digest
from smallestlie.policy.command_allowlist import CommandAllowlistError, CommandSpec
from smallestlie.policy.path_guard import PathGuardError
from smallestlie.sandbox.capture import ByteCaptureExecutor, _snapshot
from smallestlie.sandbox.executor import SandboxExecutor
from smallestlie.sandbox.limits import ResourceLimits


def command(code, *, timeout=5, cwd="."):
    return CommandSpec("raw-contract-probe", ("${PYTHON}", "-I", "-B", "-c", code),
                       cwd=cwd, timeout_seconds=timeout)


def test_raw_bytes_crlf_and_invalid_utf8_are_not_reencoded(tmp_path):
    result = ByteCaptureExecutor(tmp_path).run_bytes(command(
        "import sys; sys.stdout.buffer.write(b'\\xff\\r\\n'); sys.stderr.buffer.write(b'\\x80\\r\\n')"))
    assert result.stdout == b"\xff\r\n" and result.stderr == b"\x80\r\n"
    assert result.termination_kind == "completed" and result.exit_code == 0
    assert not result.stdout_truncated and not result.stderr_truncated
    metadata = result.metadata()
    assert metadata["stdout"]["sha256"] == digest(b"\xff\r\n")
    assert metadata["stderr"]["observed_bytes"] == 3
    assert result.argv[0] == sys.executable and Path(result.cwd) == tmp_path.resolve()


def test_effective_environment_is_scrubbed_after_extra_values(tmp_path):
    code = "import json, os; print(json.dumps(dict(os.environ)))"
    capture = ByteCaptureExecutor(tmp_path).run_bytes(command(code),
        extra_env={"CAPTURE_CASE": "bound-case", "GH_TOKEN": "secret", "HTTP_PROXY": "http://proxy",
                   "SMALLESTLIE_NETWORK": "allowed", "smallestlie_network": "allowed",
                   "tZ": "Pacific/Honolulu", "cApTuRe_CaSe": "mixed-case"})
    observed = json.loads(capture.stdout)
    assert observed["CAPTURE_CASE"] == ("mixed-case" if os.name == "nt" else "bound-case")
    assert observed["SMALLESTLIE_NETWORK"] == "denied"
    assert observed["TZ"] == "UTC"
    assert "GH_TOKEN" not in observed and "HTTP_PROXY" not in observed
    assert dict(capture.environment)["CAPTURE_CASE"] == observed["CAPTURE_CASE"]
    if os.name == "nt":
        assert "smallestlie_network" not in observed
        assert len({key.upper() for key, _ in capture.environment}) == len(capture.environment)
    assert capture.metadata()["environment_sha256"] == canonical_digest(capture.environment)
    assert "environment" not in capture.metadata()


def test_output_prefix_and_truncation_are_separate_facts(tmp_path):
    capture = ByteCaptureExecutor(tmp_path, limits=ResourceLimits(max_output_bytes=3)).run_bytes(command(
        "import sys; sys.stdout.buffer.write(b'abcd'); sys.stderr.buffer.write(b'xyz')"))
    assert capture.stdout == b"abc" and capture.stdout_total_bytes == 4 and capture.stdout_truncated
    assert capture.stderr == b"xyz" and capture.stderr_total_bytes == 3 and not capture.stderr_truncated
    assert b"truncated" not in capture.stdout
    assert capture.exit_code == 0  # A native green exit does not authorize truncated evidence.


def test_timeout_keeps_partial_raw_output_and_supervisor_disposition(tmp_path):
    capture = ByteCaptureExecutor(tmp_path).run_bytes(command(
        "import sys, time; sys.stdout.buffer.write(b'\\xffstart'); sys.stdout.flush(); time.sleep(10)", timeout=3))
    assert capture.termination_kind == "timeout"
    assert capture.stdout == b"\xffstart" and capture.stderr == b""
    assert type(capture.exit_code) is int  # Actual exit after supervisor kill, not a fabricated 124.
    assert capture.diagnostic is None


def test_spawn_error_has_no_invented_exit_or_output(tmp_path):
    capture = ByteCaptureExecutor(tmp_path).run_bytes(CommandSpec("missing", (str(tmp_path / "absent.exe"),)))
    assert capture.termination_kind == "spawn_error" and capture.exit_code is None
    assert capture.stdout == capture.stderr == b""
    assert capture.diagnostic == "FileNotFoundError"


def test_path_rejection_occurs_before_process_launch(tmp_path):
    with pytest.raises(PathGuardError):
        ByteCaptureExecutor(tmp_path).run_bytes(command("raise AssertionError('must not run')", cwd="../outside"))


@pytest.mark.parametrize("limit", [0, -1, True])
def test_invalid_supervisor_limits_reject_before_launch(tmp_path, limit):
    with pytest.raises(CommandAllowlistError, match="positive integer"):
        ByteCaptureExecutor(tmp_path, limits=ResourceLimits(timeout_seconds=limit)).run_bytes(
            command("raise AssertionError('must not run')", timeout=1))


def test_live_writer_growth_does_not_change_snapshot_length_or_writer_offset(monkeypatch):
    with tempfile.NamedTemporaryFile("w+b") as writer:
        writer.write(b"first")
        writer.flush()
        real_stat = os.fstat
        first = True

        def grow_after_size(fd):
            nonlocal first
            observed = real_stat(fd)
            if first:
                first = False
                writer.write(b"-later")
                writer.flush()
            return observed

        monkeypatch.setattr(os, "fstat", grow_after_size)
        data, total, incomplete = _snapshot(writer, 100)
        assert (data, total, incomplete) == (b"first", 5, False)
        assert writer.tell() == 11


def test_short_snapshot_is_explicitly_incomplete(monkeypatch):
    with tempfile.NamedTemporaryFile("w+b") as writer:
        writer.write(b"first")
        writer.flush()
        real_stat = os.fstat
        first = True

        def shrink_after_size(fd):
            nonlocal first
            observed = real_stat(fd)
            if first:
                first = False
                writer.truncate(0)
                writer.flush()
            return observed

        monkeypatch.setattr(os, "fstat", shrink_after_size)
        assert _snapshot(writer, 100) == (b"", 5, True)


def test_reopened_path_must_match_original_writer_descriptor():
    with tempfile.NamedTemporaryFile("w+b") as original, tempfile.NamedTemporaryFile("w+b") as replacement:
        original.write(b"authentic")
        original.flush()
        replacement.write(b"substituted")
        replacement.flush()
        # Portable model of pathname replacement: retain the authoritative
        # writer descriptor while the reopened path resolves to another file.
        moved = SimpleNamespace(fileno=original.fileno, name=replacement.name)
        with pytest.raises(OSError, match="identity changed"):
            _snapshot(moved, 100)


def test_snapshot_io_failure_is_incomplete_not_native_green(tmp_path, monkeypatch):
    def unavailable(writer, maximum):
        raise OSError("unavailable capture")

    monkeypatch.setattr("smallestlie.sandbox.capture._snapshot", unavailable)
    result = ByteCaptureExecutor(tmp_path).run_bytes(command("print('real native output')"))
    assert result.exit_code == 0 and result.termination_kind == "internal_error"
    assert result.stdout == result.stderr == b""
    assert result.stdout_total_bytes is result.stderr_total_bytes is None
    assert result.stdout_truncated and result.stderr_truncated


def test_legacy_text_api_retains_its_existing_contract(tmp_path):
    result = SandboxExecutor(tmp_path).run(command("print('legacy contract')"))
    assert result.stdout == "legacy contract\n" and result.exit_code == 0
    assert set(result.to_dict()) == {"command_id", "argv", "cwd", "exit_code", "stdout", "stderr",
                                   "timed_out", "env_keys", "execution_binding"}
