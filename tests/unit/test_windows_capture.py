"""Small native process qualification, only on an authorized execution host."""

import ctypes as c
import os
from pathlib import Path
import sys

import pytest

from smallestlie.sandbox import windows_capture as native
from smallestlie.sandbox.executor import scrub_environment


def run(tmp_path, script, *, budget=100_000, timeout=3):
    return native.capture_windows((sys.executable, "-I", "-B", "-c", script), tmp_path,
        env=scrub_environment({key.upper(): value for key, value in os.environ.items()}),
        timeout_seconds=timeout, max_output_bytes=budget, cleanup_seconds=3)


def test_native_original_bytes_and_nonzero_exit(tmp_path):
    if os.name != "nt":
        with pytest.raises(OSError, match="unsupported"):
            run(tmp_path, "pass")
        return
    captured = run(tmp_path, "import os; os.write(1,b'\\xff\\r\\n\\x00'); os.write(2,b'err\\r\\n'); raise SystemExit(7)")
    assert captured.termination_kind == "completed", captured.metadata()
    assert captured.exit_code == 7 and captured.output_complete and captured.descendants_reaped
    assert captured.stdout == b"\xff\r\n\x00" and captured.stderr == b"err\r\n"
    assert captured.observed_stdout_bytes == 4 and captured.observed_stderr_bytes == 5
    assert captured.native_pid is not None and captured.metadata()["stdout"]["bytes"] == 4


def test_parent_exit_does_not_seal_a_surviving_writer(tmp_path):
    if os.name != "nt":
        with pytest.raises(OSError, match="unsupported"):
            run(tmp_path, "pass")
        return
    child = "import os,time; time.sleep(30); os.write(1,b'late')"
    script = ("import subprocess,sys,os; subprocess.Popen([sys.executable,'-I','-B','-c',"
              + repr(child) + "],close_fds=False); os.write(1,b'parent'); os._exit(0)")
    captured = run(tmp_path, script, timeout=3)
    assert captured.termination_kind == "timeout", captured.metadata()
    assert captured.exit_code == 0 and captured.stdout == b"parent"
    assert not captured.output_complete and captured.descendants_reaped


def test_capture_quota_preserves_only_bounded_original_prefix(tmp_path):
    if os.name != "nt":
        with pytest.raises(OSError, match="unsupported"):
            run(tmp_path, "pass")
        return
    captured = run(tmp_path, "import os,time; os.write(1,b'x'*8192); time.sleep(30)", budget=64)
    assert captured.termination_kind == "quota", captured.metadata()
    assert captured.stdout == b"x" * 64 and captured.stderr == b""
    assert captured.observed_stdout_bytes > 64
    assert not captured.output_complete and captured.descendants_reaped
    assert not list(tmp_path.iterdir())  # No unbounded capture file was created.


@pytest.mark.parametrize("change", ["bool_timeout", "relative_exe", "relative_cwd", "env_alias", "env_nul", "output_limit"])
def test_invalid_launch_inputs_never_load_kernel(tmp_path, monkeypatch, change):
    def forbidden():
        raise AssertionError("invalid request loaded kernel32")
    monkeypatch.setattr(native, "_kernel", forbidden)
    argv, cwd, env = (sys.executable, "-c", "pass"), tmp_path, {}
    timeout, budget = 1, 100
    if change == "bool_timeout": timeout = True
    elif change == "relative_exe": argv = ("python", "-c", "pass")
    elif change == "relative_cwd": cwd = Path("relative")
    elif change == "env_alias": env = {"Path": "x", "PATH": "y"}
    elif change == "env_nul": env = {"PATH": "x\0y"}
    else: budget = 10_000_001
    with pytest.raises(ValueError):
        native.capture_windows(argv, cwd, env=env, timeout_seconds=timeout, max_output_bytes=budget)


class KernelFailure:
    """Control only failure boundaries; positive process facts use native APIs."""
    def __init__(self, stage):
        self.stage, self.deleted, self.resumed, self.closed, self.terminated = stage, False, False, [], []
        self.next_handle = 10

    def CreateJobObjectW(self, *args): return 1
    def SetInformationJobObject(self, *args): return True
    def SetHandleInformation(self, *args): return True
    def CreatePipe(self, reader, writer, *args):
        reader._obj.value, writer._obj.value = self.next_handle, self.next_handle + 1
        self.next_handle += 2
        return True
    def CreateFileW(self, *args): return 20
    def InitializeProcThreadAttributeList(self, pointer, count, flags, size):
        size._obj.value = 64
        return bool(pointer) and self.stage != "initialize"
    def UpdateProcThreadAttribute(self, *args): return True
    def DeleteProcThreadAttributeList(self, *args): self.deleted = True
    def CreateProcessW(self, *args):
        process = args[-1]._obj
        process.process, process.thread, process.pid = 21, 22, 23
        return True
    def AssignProcessToJobObject(self, *args): return self.stage == "cleanup"
    def ResumeThread(self, *args): self.resumed = True; return 1
    def TerminateProcess(self, handle, *args): self.terminated.append(handle); return True
    def TerminateJobObject(self, *args): return self.stage != "cleanup"
    def CloseHandle(self, handle): self.closed.append(handle); return True
    def PeekNamedPipe(self, *args): c.set_last_error(109); return False
    def WaitForSingleObject(self, *args): return 0
    def GetExitCodeProcess(self, handle, code): code._obj.value = 130; return True
    def QueryInformationJobObject(self, job, kind, info, *args):
        info._obj.active = 1 if self.stage == "cleanup" else 0
        return True


@pytest.mark.parametrize("stage", ["initialize", "assign"])
def test_failed_native_setup_never_resumes_and_cleans_only_initialized_attributes(tmp_path, monkeypatch, stage):
    if os.name != "nt":
        with pytest.raises(OSError, match="unsupported"):
            run(tmp_path, "pass")
        return
    kernel = KernelFailure(stage)
    monkeypatch.setattr(native, "_kernel", lambda: kernel)
    captured = run(tmp_path, "raise AssertionError('must never start')")
    assert captured.termination_kind == "spawn_error" and not captured.output_complete
    assert kernel.resumed is False and kernel.deleted is (stage == "assign")
    assert 1 in kernel.closed and 20 in kernel.closed
    if stage == "assign":
        assert kernel.terminated == [21] and captured.descendants_reaped
    else:
        assert kernel.terminated == [] and captured.native_pid is None


def test_failed_job_termination_does_not_claim_writer_closure(tmp_path, monkeypatch):
    if os.name != "nt":
        with pytest.raises(OSError, match="unsupported"):
            run(tmp_path, "pass")
        return
    kernel = KernelFailure("cleanup")
    monkeypatch.setattr(native, "_kernel", lambda: kernel)
    captured = run(tmp_path, "pass", timeout=1)
    assert kernel.resumed and kernel.deleted
    assert captured.termination_kind == "internal_error"
    assert not captured.descendants_reaped and not captured.output_complete
    assert captured.diagnostic is not None
