"""One Windows action job, bounded raw pipe capture and measured writer closure.

This is a producer primitive, not an execution authority or a filesystem/network
sandbox. A separately admitted host must supply those isolation/storage facts.
No API imports kernel32 or launches work until capture_windows() is called.
"""

from __future__ import annotations

import ctypes as c
from ctypes import wintypes as w
from dataclasses import dataclass
import os
from pathlib import Path
import subprocess
import time

from smallestlie.campaign.preregistration import canonical_digest, digest, integer


class _Security(c.Structure):
    _fields_ = [("length", w.DWORD), ("descriptor", c.c_void_p), ("inherit", w.BOOL)]


class _IO(c.Structure):
    _fields_ = [(name, c.c_ulonglong) for name in ("ro", "wo", "oo", "rt", "wt", "ot")]


class _Basic(c.Structure):
    _fields_ = [("process_time", c.c_longlong), ("job_time", c.c_longlong),
                ("flags", w.DWORD), ("min_ws", c.c_size_t), ("max_ws", c.c_size_t),
                ("active_limit", w.DWORD), ("affinity", c.c_size_t),
                ("priority", w.DWORD), ("scheduling", w.DWORD)]


class _Limits(c.Structure):
    _fields_ = [("basic", _Basic), ("io", _IO), ("process_memory", c.c_size_t),
                ("job_memory", c.c_size_t), ("peak_process", c.c_size_t), ("peak_job", c.c_size_t)]


class _Accounting(c.Structure):
    _fields_ = [(name, c.c_longlong) for name in ("user", "kernel", "period_user", "period_kernel")] + [
        (name, w.DWORD) for name in ("faults", "total", "active", "terminated")]


class _Startup(c.Structure):
    _fields_ = [("cb", w.DWORD), ("reserved", w.LPWSTR), ("desktop", w.LPWSTR),
                ("title", w.LPWSTR), *[(name, w.DWORD) for name in
                ("x", "y", "xs", "ys", "xc", "yc", "fill", "flags")],
                ("show", w.WORD), ("reserved_size", w.WORD), ("reserved2", c.c_void_p),
                ("stdin", w.HANDLE), ("stdout", w.HANDLE), ("stderr", w.HANDLE)]


class _StartupEx(c.Structure):
    _fields_ = [("startup", _Startup), ("attributes", c.c_void_p)]


class _Process(c.Structure):
    _fields_ = [("process", w.HANDLE), ("thread", w.HANDLE), ("pid", w.DWORD), ("tid", w.DWORD)]


def _kernel():
    k = c.WinDLL("kernel32", use_last_error=True)
    signatures = {
        "CreateJobObjectW": ([c.c_void_p, w.LPCWSTR], w.HANDLE),
        "SetInformationJobObject": ([w.HANDLE, c.c_int, c.c_void_p, w.DWORD], w.BOOL),
        "QueryInformationJobObject": ([w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.POINTER(w.DWORD)], w.BOOL),
        "AssignProcessToJobObject": ([w.HANDLE, w.HANDLE], w.BOOL),
        "TerminateJobObject": ([w.HANDLE, w.UINT], w.BOOL),
        "TerminateProcess": ([w.HANDLE, w.UINT], w.BOOL),
        "ResumeThread": ([w.HANDLE], w.DWORD),
        "WaitForSingleObject": ([w.HANDLE, w.DWORD], w.DWORD),
        "GetExitCodeProcess": ([w.HANDLE, c.POINTER(w.DWORD)], w.BOOL),
        "CloseHandle": ([w.HANDLE], w.BOOL),
        "CreatePipe": ([c.POINTER(w.HANDLE), c.POINTER(w.HANDLE), c.POINTER(_Security), w.DWORD], w.BOOL),
        "SetHandleInformation": ([w.HANDLE, w.DWORD, w.DWORD], w.BOOL),
        "CreateFileW": ([w.LPCWSTR, w.DWORD, w.DWORD, c.POINTER(_Security), w.DWORD, w.DWORD, w.HANDLE], w.HANDLE),
        "PeekNamedPipe": ([w.HANDLE, c.c_void_p, w.DWORD, c.POINTER(w.DWORD), c.POINTER(w.DWORD), c.POINTER(w.DWORD)], w.BOOL),
        "ReadFile": ([w.HANDLE, c.c_void_p, w.DWORD, c.POINTER(w.DWORD), c.c_void_p], w.BOOL),
        "InitializeProcThreadAttributeList": ([c.c_void_p, w.DWORD, w.DWORD, c.POINTER(c.c_size_t)], w.BOOL),
        "UpdateProcThreadAttribute": ([c.c_void_p, w.DWORD, c.c_size_t, c.c_void_p, c.c_size_t, c.c_void_p, c.c_void_p], w.BOOL),
        "DeleteProcThreadAttributeList": ([c.c_void_p], None),
        "CreateProcessW": ([w.LPCWSTR, w.LPWSTR, c.c_void_p, c.c_void_p, w.BOOL,
                            w.DWORD, c.c_void_p, w.LPCWSTR, c.POINTER(_StartupEx), c.POINTER(_Process)], w.BOOL),
    }
    for name, (args, result) in signatures.items():
        getattr(k, name).argtypes, getattr(k, name).restype = args, result
    return k


def _check(value):
    if not value:
        raise c.WinError(c.get_last_error())
    return value


def _environment(env):
    if type(env) is not dict:
        raise ValueError("explicit environment mapping required")
    normalized = {}
    for key, value in env.items():
        if (type(key) is not str or type(value) is not str or not key or "=" in key
                or "\0" in key or "\0" in value or key.upper() in normalized):
            raise ValueError("invalid or case-aliased Windows environment")
        normalized[key.upper()] = value
    text = "".join(f"{key}={value}\0" for key, value in sorted(normalized.items())) + "\0"
    # An empty environment still requires two terminating wide NULs.
    return normalized, c.create_unicode_buffer(text if normalized else "\0\0")


@dataclass(frozen=True)
class WindowsCapture:
    argv: tuple[str, ...]
    cwd: str
    environment_sha256: str
    termination_kind: str
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    observed_stdout_bytes: int
    observed_stderr_bytes: int
    output_complete: bool
    descendants_reaped: bool
    native_pid: int | None
    diagnostic: str | None

    def metadata(self):
        return {"schema_version": "smallestlie.windows-action-capture/v1",
            "argv": list(self.argv), "cwd": self.cwd, "environment_sha256": self.environment_sha256,
            "termination_kind": self.termination_kind, "exit_code": self.exit_code,
            "output_complete": self.output_complete, "descendants_reaped": self.descendants_reaped,
            "native_pid": self.native_pid, "diagnostic": self.diagnostic,
            "stdout": {"bytes": len(self.stdout), "observed_bytes": self.observed_stdout_bytes,
                       "sha256": digest(self.stdout)},
            "stderr": {"bytes": len(self.stderr), "observed_bytes": self.observed_stderr_bytes,
                       "sha256": digest(self.stderr)}}


def capture_windows(argv: tuple[str, ...], cwd: str | Path, *, env: dict[str, str],
                    timeout_seconds: int, max_output_bytes: int, cleanup_seconds: int = 5) -> WindowsCapture:
    """Wait for the whole action job and both pipe EOFs, not only parent exit.

    Retain at most max_output_bytes combined. Exceeding it terminates the action
    as quota and preserves the bounded original prefix. No growing capture file
    exists. The caller supplies a scrubbed environment and accepted host policy.
    """
    for label, value in (("timeout", timeout_seconds), ("output budget", max_output_bytes), ("cleanup", cleanup_seconds)):
        integer(value, label, minimum=1)
    if max_output_bytes > 10_000_000:
        raise ValueError("capture budget exceeds bounded raw artifact limit")
    if type(argv) is not tuple or not argv or any(type(arg) is not str or not arg or "\0" in arg for arg in argv):
        raise ValueError("explicit nonempty argv tuple required")
    if not Path(argv[0]).is_absolute() or not Path(cwd).is_absolute():
        raise ValueError("absolute executable and cwd required")
    normalized, block = _environment(env)
    if os.name != "nt":
        raise OSError("Windows action job capture is unsupported on this host")
    k, child = _kernel(), _Process()
    handles, reads, writes = set(), [], []
    job, attributes, attributes_initialized = None, None, False
    kind, code, diagnostic = "spawn_error", None, None
    pid, started, closed, complete = None, False, False, False
    chunks, observed, eof = [bytearray(), bytearray()], [0, 0], [False, False]

    def close(handle):
        if handle in handles:
            _check(k.CloseHandle(handle))
            handles.remove(handle)

    def active():
        info = _Accounting()
        _check(k.QueryInformationJobObject(job, 1, c.byref(info), c.sizeof(info), None))
        return info.active

    def drain():
        exceeded = False
        for index, handle in enumerate(reads):
            if eof[index]:
                continue
            # Bounded work per poll preserves timeout fairness under a flood.
            for _ in range(16):
                available = w.DWORD()
                if not k.PeekNamedPipe(handle, None, 0, None, c.byref(available), None):
                    if c.get_last_error() == 109:  # ERROR_BROKEN_PIPE: every writer handle closed.
                        eof[index] = True
                        break
                    raise c.WinError(c.get_last_error())
                if not available.value:
                    break
                count = min(available.value, 4096)
                raw, read = c.create_string_buffer(count), w.DWORD()
                _check(k.ReadFile(handle, raw, count, c.byref(read), None))
                if not read.value:
                    raise OSError("short zero-byte pipe read")
                data = raw.raw[:read.value]
                observed[index] += len(data)
                room = max(0, max_output_bytes - len(chunks[0]) - len(chunks[1]))
                chunks[index].extend(data[:room])
                exceeded |= sum(observed) > max_output_bytes
                if exceeded:
                    break
        return exceeded

    def observe_parent():
        nonlocal code
        if child.process:
            waited = k.WaitForSingleObject(child.process, 0)
            if waited == 0:
                value = w.DWORD()
                _check(k.GetExitCodeProcess(child.process, c.byref(value)))
                code = value.value
                # Release references before accounting's ActiveProcesses readback.
                close(child.thread)
                close(child.process)
                child.thread, child.process = None, None
            elif waited != 0x102:
                raise c.WinError(c.get_last_error())

    try:
        job = _check(k.CreateJobObjectW(None, None))
        handles.add(job)
        limits = _Limits()
        limits.basic.flags = 0x2000  # KILL_ON_JOB_CLOSE; no breakaway permission.
        _check(k.SetInformationJobObject(job, 9, c.byref(limits), c.sizeof(limits)))
        security = _Security(c.sizeof(_Security), None, True)
        for _ in range(2):
            reader, writer = w.HANDLE(), w.HANDLE()
            _check(k.CreatePipe(c.byref(reader), c.byref(writer), c.byref(security), 4096))
            reads.append(reader.value)
            writes.append(writer.value)
            handles.update((reader.value, writer.value))
            _check(k.SetHandleInformation(reader, 1, 0))
        stdin = k.CreateFileW("NUL", 0x80000000, 7, c.byref(security), 3, 0x80, None)
        if stdin == c.c_void_p(-1).value:
            raise c.WinError(c.get_last_error())
        handles.add(stdin)
        size = c.c_size_t()
        k.InitializeProcThreadAttributeList(None, 1, 0, c.byref(size))
        if not size.value:
            raise c.WinError(c.get_last_error())
        allocation = c.create_string_buffer(size.value)
        attributes = c.cast(allocation, c.c_void_p)
        _check(k.InitializeProcThreadAttributeList(attributes, 1, 0, c.byref(size)))
        attributes_initialized = True
        inherited = (w.HANDLE * 3)(stdin, *writes)
        _check(k.UpdateProcThreadAttribute(attributes, 0, 0x20002, c.cast(inherited, c.c_void_p),
                                           c.sizeof(inherited), None, None))
        startup = _StartupEx()
        startup.startup.cb, startup.startup.flags = c.sizeof(startup), 0x100
        startup.startup.stdin, startup.startup.stdout, startup.startup.stderr = stdin, *writes
        startup.attributes = attributes
        _check(k.CreateProcessW(argv[0], c.create_unicode_buffer(subprocess.list2cmdline(argv)), None, None, True,
                                0x4 | 0x400 | 0x80000 | 0x8000000, c.cast(block, c.c_void_p), str(cwd),
                                c.byref(startup), c.byref(child)))
        handles.update((child.process, child.thread))
        pid = child.pid
        _check(k.AssignProcessToJobObject(job, child.process))
        if k.ResumeThread(child.thread) == 0xFFFFFFFF:
            raise c.WinError(c.get_last_error())
        started, kind = True, "completed"
        for handle in [stdin, *writes]:
            close(handle)
        deadline = time.monotonic() + timeout_seconds
        while True:
            exceeded = drain()
            observe_parent()
            if exceeded:
                kind = "quota"
                break
            if code is not None and active() == 0 and all(eof):
                closed, complete = True, True
                break
            if time.monotonic() >= deadline:
                kind = "timeout"
                break
            time.sleep(0.005)
    except (OSError, ValueError) as exc:
        kind, diagnostic = ("internal_error" if started else "spawn_error"), type(exc).__name__
    finally:
        if attributes_initialized:
            k.DeleteProcThreadAttributeList(attributes)
        if not closed:
            try:
                # A failed assignment leaves a suspended, unrun child outside the job.
                if child.process and not started:
                    _check(k.TerminateProcess(child.process, 130))
                if job:
                    _check(k.TerminateJobObject(job, 130))
                for handle in writes:
                    close(handle)
                deadline = time.monotonic() + cleanup_seconds
                while job:
                    drain()
                    observe_parent()
                    if active() == 0 and all(eof) and child.process is None:
                        closed = True
                        break
                    if time.monotonic() >= deadline:
                        break
                    time.sleep(0.005)
            except (OSError, ValueError) as exc:
                diagnostic = type(exc).__name__
            if not closed and started:
                kind, diagnostic = "internal_error", diagnostic or "writer_cleanup_incomplete"
        for handle in list(handles):
            try:
                close(handle)
            except OSError:
                complete, closed = False, False
                kind, diagnostic = "internal_error", "handle_close_failed"
    return WindowsCapture(argv, str(cwd), canonical_digest(normalized), kind, code,
        bytes(chunks[0]), bytes(chunks[1]), *observed, complete, closed, pid, diagnostic)
