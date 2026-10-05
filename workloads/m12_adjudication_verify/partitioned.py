"""Dedicated HOST50 regression partition with one entry-wide deadline.

SOURCE_ONLY / NOT_RUN until CI and admitted, accounted pool dispatches. The
entry's 1800 seconds start here, after EC preparation; they do not authenticate
a workflow-start clock or guarantee the 300-second conditional outer headroom.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import time
import tomllib
import xml.etree.ElementTree as ET

from workloads.m12_adjudication_verify.protocol import (
    canonical, collection_result, digest, load, parameters, partition_result,
)


ROOT = Path(__file__).resolve().parents[2]
HOST = "LAPTOP-50KP71KA"
WORKLOAD = "m12-adjudication-verify"
PLUGIN = "workloads.m12_adjudication_verify.pytest_partition"
LOCK_SHA256 = "c09258281d58dd19d6ed19e60d2fc14ef783d4f63df8ca171548e399ec055b48"
DEPENDENCIES = {
    "pytest", "pytest-timeout", "pyyaml", "colorama", "iniconfig", "packaging", "pluggy", "pygments",
}
FOCUSED = (
    "tests/unit/test_adjudication.py", "tests/unit/test_checkwash_adapter.py",
    "tests/unit/test_runner_evidence.py", "tests/unit/test_residual_sources.py",
    "tests/unit/test_execution_verdict.py",
)
ENTRY_SECONDS = 1800
FINALIZATION_RESERVE = 120
CHILD_CLOSE_RESERVE = 20
MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_EVENTS_BYTES = 64 * 1024 * 1024
MAX_JUNIT_BYTES = 64 * 1024 * 1024


class BudgetExhausted(RuntimeError):
    pass


class Budget:
    def __init__(self, *, seconds=ENTRY_SECONDS, clock=time.monotonic):
        self.clock = clock
        self.started = clock()
        self.deadline = self.started + seconds

    def remaining(self) -> float:
        return max(0.0, self.deadline - self.clock())

    def timeout(self, phase_cap: float, *, final=False, closing=False) -> float:
        reserve = 0 if closing else CHILD_CLOSE_RESERVE + (0 if final else FINALIZATION_RESERVE)
        remaining = self.remaining() - reserve
        if phase_cap <= 0 or remaining <= 0:
            raise BudgetExhausted("entry deadline cannot reserve bounded child close/finalization")
        return min(float(phase_cap), remaining)


def child_environment(parent: dict[str, str], root: Path) -> dict[str, str]:
    """Allowlisted OS necessities only: no App key, token, file command or pytest override."""
    allowed = {
        "PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP", "PATHEXT",
        "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "LOCALAPPDATA", "APPDATA", "PROGRAMDATA",
        "COMPUTERNAME", "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS",
    }
    env = {name: value for name, value in parent.items() if name.upper() in allowed}
    env.update(PYTHONUTF8="1", PYTHONDONTWRITEBYTECODE="1", PYTHONHASHSEED="49314",
               PYTHONPATH=os.pathsep.join((str(root), str(root / "src"), str(root / "fixtures"))),
               PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", GIT_TERMINAL_PROMPT="0",
               GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="core.hooksPath", GIT_CONFIG_VALUE_0="NUL")
    return env


def read_bounded(path: Path, cap: int) -> bytes:
    with path.open("rb") as handle:
        raw = handle.read(cap + 1)
    if len(raw) > cap:
        raise ValueError(f"evidence exceeds fixed byte cap: {path.name}")
    return raw


def write_new(path: Path, raw: bytes):
    with path.open("xb") as handle:
        handle.write(raw)


def acquire_input(name: str, path: Path | None, out: Path, artifact: str, cap: int,
                  observations: dict, budget: Budget) -> bytes:
    """Preserve exactly received bytes; a bounded prefix is never a whole-file hash."""
    observation = {"status": "NOT_RECEIVED", "received_bytes": None,
                   "received_sha256": None, "sha256": None, "received_complete": False,
                   "artifact": None, "semantic_validated": None, "error_type": None}
    observations[name] = observation
    try:
        if path is None:
            raise ValueError("missing fixed input path")
        if budget.remaining() <= 0:
            raise BudgetExhausted("entry deadline exhausted before input acquisition")
        with path.open("rb") as handle:
            raw = handle.read(cap + 1)
        complete = len(raw) <= cap
        observation.update(status="RECEIVED" if complete else "RECEIVED_PREFIX",
                           received_bytes=len(raw), received_sha256=digest(raw),
                           sha256=digest(raw) if complete else None, received_complete=complete)
        write_new(out / artifact, raw)
        observation["artifact"] = artifact
        if not complete:
            raise ValueError("fixed input exceeds the bounded received prefix")
        return raw
    except (OSError, ValueError, BudgetExhausted) as exc:
        observation["error_type"] = type(exc).__name__
        raise


def finalize(out: Path, result: dict, budget: Budget) -> int:
    """Close local artifacts, then require an independently observed native exit.

    result.json is never sufficient to assert completion. The terminal marker
    binds raw artifact digests and a closed predicate including the actual EC
    wrapper exit/elapsed. Every final write is followed by the same clock check;
    a late final synchronous IO returns nonzero and retains a separate refusal.
    """
    phase_ready = result["phase_checks_complete"] is True
    result["partition_complete"] = False
    result["terminal_state"] = "PROVISIONAL"
    result["native_terminal_required"] = True
    provisional = canonical(result)
    final_raw = None
    stage = "provisional-result"

    def refused(error_type: str, failed_stage: str) -> int:
        refusal = {"schema_version": 1, "scope": "partition_only", "partition_complete": False,
                   "error_type": error_type, "stage": failed_stage,
                   "entry_elapsed_seconds": round(budget.clock() - budget.started, 6),
                   "entry_budget_seconds": ENTRY_SECONDS, "native_exit_required": "nonzero"}
        # Keep the original provisional epoch and any actually written pending
        # result. Atomic replacement affects only this unpublished result path.
        result["partition_complete"] = False
        result["terminal_state"] = "REFUSED"
        result.setdefault("errors", []).append({"phase": "finalization", "error_type": error_type})
        result.setdefault("problems", []).append("result finalization refused")
        try:
            if final_raw is not None and (out / "result.json").exists():
                write_new(out / "result.pre-refusal.json", read_bounded(out / "result.json", MAX_JSON_BYTES))
            name = "late-refusal.json" if error_type == "EntryDeadlineExceeded" else "finalization-refusal.json"
            write_new(out / name, canonical(refusal))
            temporary = out / "result.refused.tmp"
            write_new(temporary, canonical(result))
            os.replace(temporary, out / "result.json")
        except (OSError, ValueError):
            # An unavailable output filesystem cannot be repaired by a success
            # claim. The actual nonzero wrapper exit and missing closure refuse.
            pass
        return 1

    try:
        write_new(out / "result.provisional.json", provisional)
        if budget.remaining() <= 0:
            return refused("EntryDeadlineExceeded", stage)
        result["terminal_state"] = "NATIVE_TERMINAL_REQUIRED" if phase_ready else "REFUSED_PHASES"
        result["entry_elapsed_before_result_write"] = round(budget.clock() - budget.started, 6)
        final_raw = canonical(result)
        stage = "result"
        write_new(out / "result.commit.tmp", final_raw)
        os.replace(out / "result.commit.tmp", out / "result.json")
        if budget.remaining() <= 0:
            return refused("EntryDeadlineExceeded", stage)
        lines = ["# SmallestLie Windows regression partition", "",
                 f"Result: {'partition_phase_checks_complete' if phase_ready else 'partition_incomplete'}",
                 "partition_complete: false until the independent native terminal predicate is satisfied.",
                 f"Shard: `{result['shard']}`; source: `{result['actual_sha']}`; host: `{result['host']}`.",
                 "Full Windows verdict: NOT_ESTABLISHED.", "",
                 "Terminal predicate: terminal.json, no refusal, actual EC wrapper exit zero",
                 "and actual wrapper elapsed <=1800 seconds. Internal markers alone do not complete it.", ""]
        lines += [f"- Problem: {problem}" for problem in result["problems"]]
        lines += ["", *[f"- Limit: {limit}" for limit in result["limitations"]], ""]
        summary = "\n".join(lines).encode("utf-8")
        stage = "summary"
        write_new(out / "SUMMARY.md", summary)
        if budget.remaining() <= 0:
            return refused("EntryDeadlineExceeded", stage)
        marker = {
            "schema_version": 1, "scope": "partition_only", "partition_complete": False,
            "ready_for_native_terminal": phase_ready,
            "result_sha256": digest(final_raw), "summary_sha256": digest(summary),
            "provisional_sha256": digest(provisional), "entry_budget_seconds": ENTRY_SECONDS,
            "entry_elapsed_before_terminal_write": round(budget.clock() - budget.started, 6),
            "completion_predicate": {
                "phase_checks_complete": True, "ready_for_native_terminal": True,
                "required_actual_wrapper_exit_code": 0, "actual_wrapper_elapsed_at_most": ENTRY_SECONDS,
                "refusal_artifacts_absent": True, "raw_result_summary_provisional_digests_match": True,
            },
        }
        stage = "terminal-marker"
        write_new(out / "terminal.json", canonical(marker))
        if budget.remaining() <= 0:
            return refused("EntryDeadlineExceeded", stage)
        # The caller still requires actual native exit/elapsed evidence: even
        # the interval after this last clock sample cannot self-authenticate.
        return 0 if phase_ready else 1
    except (OSError, ValueError) as exc:
        return refused(type(exc).__name__, stage)


class Runner:
    """Raw streams go directly to files, retaining prefixes even after hard kill."""

    def __init__(self, root: Path, out: Path, env: dict[str, str], budget: Budget):
        self.root, self.out, self.env, self.budget = root, out, env, budget
        self.steps: list[dict] = []

    def run(self, name: str, command: list[str], cap: float, *, final=False) -> int:
        began = self.budget.clock()
        record = {"name": name, "command": command, "exit_code": 2, "timed_out": False,
                  "started": False, "entry_remaining_before": round(self.budget.remaining(), 3)}
        stdout_path, stderr_path = self.out / f"{name}.stdout", self.out / f"{name}.stderr"
        with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            process = None
            try:
                timeout = self.budget.timeout(cap, final=final)
                phase_deadline = min(began + cap, self.budget.clock() + timeout)
                record["allocated_seconds"] = max(0.0, phase_deadline - began)
                if phase_deadline <= self.budget.clock():
                    raise BudgetExhausted("phase cap expired before native child start")
                kwargs = ({"creationflags": subprocess.CREATE_NO_WINDOW} if sys.platform == "win32"
                          else {"start_new_session": True})
                process = subprocess.Popen(command, cwd=self.root, env=self.env,
                                           stdout=stdout, stderr=stderr, **kwargs)
                record.update(started=True, pid=process.pid)
                try:
                    remaining_wait = min(phase_deadline - self.budget.clock(),
                                         self.budget.timeout(cap, final=final))
                    if remaining_wait <= 0:
                        raise subprocess.TimeoutExpired(command, timeout)
                    process.wait(timeout=remaining_wait)
                    record["exit_code"] = process.returncode
                except subprocess.TimeoutExpired:
                    record.update(exit_code=124, timed_out=True)
                    record["cleanup"] = self._close_child(process, stderr)
            except (OSError, BudgetExhausted) as exc:
                stderr.write((f"error_type: {type(exc).__name__}\n").encode("utf-8"))
                if process is not None and process.poll() is None:
                    record["cleanup"] = self._close_child(process, stderr)
                if isinstance(exc, BudgetExhausted):
                    record["budget_exhausted"] = True
        record["elapsed_seconds"] = round(self.budget.clock() - began, 3)
        record["entry_remaining_after"] = round(self.budget.remaining(), 3)
        # Hash the already written raw files incrementally, including failure prefixes.
        for label, path in (("stdout", stdout_path), ("stderr", stderr_path)):
            sha = hashlib.sha256()
            with path.open("rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    sha.update(chunk)
            record[f"{label}_sha256"] = sha.hexdigest()
        self.steps.append(record)
        return record["exit_code"]

    def _close_child(self, process, stderr) -> dict:
        state = {"tree_kill": "UNCONFIRMED", "parent_reaped": False}
        try:
            if sys.platform == "win32":
                system_root = next((value for name, value in self.env.items()
                                    if name.upper() == "SYSTEMROOT"), None)
                if not system_root:
                    raise OSError("no SystemRoot for fixed taskkill")
                killer = str(Path(system_root) / "System32" / "taskkill.exe")
                timeout = self.budget.timeout(15, closing=True)
                with (self.out / f"pid-{process.pid}-taskkill.stdout").open("xb") as killed_out, \
                        (self.out / f"pid-{process.pid}-taskkill.stderr").open("xb") as killed_err:
                    killed = subprocess.run([killer, "/PID", str(process.pid), "/T", "/F"],
                                            stdout=killed_out, stderr=killed_err, timeout=timeout,
                                            creationflags=subprocess.CREATE_NO_WINDOW, check=False)
                state["tree_kill_exit"] = killed.returncode
                if killed.returncode == 0:
                    state["tree_kill"] = "COMMAND_SUCCEEDED"
            else:
                # Portable synthetic CI contracts only; production main requires Windows.
                os.killpg(process.pid, signal.SIGKILL)
                state["tree_kill"] = "COMMAND_SUCCEEDED"
        except (OSError, subprocess.TimeoutExpired, BudgetExhausted) as exc:
            stderr.write((f"Bounded tree cleanup unconfirmed: {type(exc).__name__}\n").encode("utf-8"))
        if process.poll() is None:
            try:
                process.kill()
            except OSError as exc:
                stderr.write((f"Parent kill unconfirmed: {type(exc).__name__}\n").encode("utf-8"))
        try:
            process.wait(timeout=self.budget.timeout(5, closing=True))
            state["parent_reaped"] = True
        except (OSError, subprocess.TimeoutExpired, BudgetExhausted) as exc:
            stderr.write((f"Bounded reap incomplete: {type(exc).__name__}\n").encode("utf-8"))
        return state


def locked_requirements(raw: bytes) -> list[str]:
    if digest(raw) != LOCK_SHA256:
        raise ValueError("the original eight-wheel uv.lock changed")
    packages = tomllib.loads(raw.decode("utf-8"))["package"]
    chosen = [package for package in packages if package["name"] in DEPENDENCIES]
    if {p["name"] for p in chosen} != DEPENDENCIES or len(chosen) != len(DEPENDENCIES):
        raise ValueError("lock must contain exactly the eight original dependency packages")
    result = []
    for package in sorted(chosen, key=lambda p: p["name"]):
        suffix = "-cp312-cp312-win_amd64.whl" if package["name"] == "pyyaml" else "-none-any.whl"
        wheels = [wheel for wheel in package["wheels"] if wheel["url"].endswith(suffix)]
        if len(wheels) != 1:
            raise ValueError("expected exactly one original compatible wheel")
        wheel = wheels[0]
        if (not wheel["url"].startswith("https://files.pythonhosted.org/packages/")
                or re.fullmatch(r"sha256:[0-9a-f]{64}", wheel["hash"]) is None):
            raise ValueError("unexpected original wheel host or hash")
        result.append(f"{package['name']} @ {wheel['url']} --hash={wheel['hash']}")
    return result


def focused_result(path: Path, code: int, raw_session: bytes, raw_events: bytes) -> dict:
    root = ET.fromstring(read_bounded(path, MAX_JUNIT_BYTES))
    cases = root.findall(".//testcase")
    counts = {"tests": len(cases), "failures": sum(c.find("failure") is not None for c in cases),
              "errors": sum(c.find("error") is not None for c in cases),
              "skipped": sum(c.find("skipped") is not None for c in cases)}
    if code or not cases or any(counts[name] for name in ("failures", "errors", "skipped")):
        raise ValueError("focused exit/JUnit incomplete, failed, errored or skipped")
    terminal = load(raw_session)
    expected = {"schema_version": 1, "plugin_loaded": True, "scope": "focused_diagnostic",
                "tests_collected": len(cases), "exitstatus": 0}
    if terminal != expected or raw_session != canonical(expected):
        raise ValueError("focused actual outcome guard handshake missing or incomplete")
    records = [load(line) for line in raw_events.splitlines()]
    if len(records) != 3 * len(cases) + 1 or records[-1] != {"event": "session_finish", **expected}:
        raise ValueError("focused actual phase coverage incomplete")
    for start in range(0, len(records) - 1, 3):
        group = records[start:start + 3]
        if (any(type(row) is not dict or set(row) != {"event", "nodeid", "when", "outcome", "wasxfail"}
                or row["event"] != "phase" or row["outcome"] != "passed"
                or row["wasxfail"] is not False or type(row["nodeid"]) is not str or not row["nodeid"]
                for row in group)
                or [row["when"] for row in group] != ["setup", "call", "teardown"]
                or len({row["nodeid"] for row in group}) != 1):
            raise ValueError("focused failure, skip, xfail/xpass or ambiguous raw phase")
    return counts


def main() -> int:
    budget = Budget()  # Entry origin, not workflow origin. Every subprocess uses this same object.
    required = ("EC_WORKLOAD_SOURCE", "EC_WORKLOAD_OUT", "EC_WORKLOAD_WORK", "EC_WORKLOAD_SHA")
    if (any(not os.environ.get(name) for name in required)
            or os.environ.get("EC_WORKLOAD_REPOSITORY") != "taipei49314/smallestlie"
            or os.environ.get("EC_WORKLOAD_NAME") != WORKLOAD
            or os.environ.get("EC_WORKLOAD_MODE") != "single"
            or os.environ.get("EC_WORKLOAD_CACHE")
            or Path(os.environ["EC_WORKLOAD_SOURCE"]).resolve() != ROOT):
        raise RuntimeError("require the admitted, uncached single EC workload route")
    host = platform.node().upper()
    if host != HOST or os.environ.get("COMPUTERNAME", "").upper() != HOST:
        raise RuntimeError(f"requires {HOST}, observed {host}")
    if (sys.platform != "win32" or sys.implementation.name != "cpython"
            or sys.version_info[:2] != (3, 12)
            or platform.machine().lower() not in {"amd64", "x86_64"}):
        raise RuntimeError("requires CPython 3.12 Windows x64")
    expected = os.environ["EC_WORKLOAD_SHA"]
    if re.fullmatch(r"[0-9a-f]{40}", expected) is None:
        raise RuntimeError("requires an exact reviewed source SHA")
    out, work = (Path(os.environ[name]).resolve() for name in ("EC_WORKLOAD_OUT", "EC_WORKLOAD_WORK"))
    out.mkdir(parents=True, exist_ok=True)
    work.mkdir(parents=True, exist_ok=True)
    runner = Runner(ROOT, out, child_environment(dict(os.environ), ROOT), budget)
    problems, suites, requirements, errors = [], {}, [], []
    actual, shard, raw_parameters, lock, plugin_sha = None, None, None, None, None
    acquisitions = {}
    source_observations = {"initial": None, "final": None}
    early_refusal = False

    def refusal(phase, reason, exc=None):
        problems.append(reason)
        errors.append({"phase": phase, "error_type": type(exc).__name__ if exc is not None else None})

    def source_check(prefix, *, final=False):
        observation = {"sha": None, "matches_requested": None, "source_exit": None,
                       "status_exit": None, "status_sha256": None, "clean": None}
        source_observations[prefix] = observation
        source_code = runner.run(f"{prefix}-source", ["git", "rev-parse", "--verify", "HEAD"], 15,
                                 final=final)
        observation["source_exit"] = source_code
        observed = read_bounded(out / f"{prefix}-source.stdout", 1024).decode("ascii").strip()
        if source_code == 0 and re.fullmatch(r"[0-9a-f]{40}", observed):
            observation["sha"] = observed
            observation["matches_requested"] = observed == expected
        status_code = runner.run(f"{prefix}-status", ["git", "status", "--porcelain", "-z"], 15,
                                 final=final)
        status_raw = read_bounded(out / f"{prefix}-status.stdout", MAX_JSON_BYTES)
        observation["status_exit"] = status_code
        if runner.steps[-1]["started"]:
            observation["status_sha256"] = digest(status_raw)
        if status_code == 0:
            observation["clean"] = not status_raw
        if observation["matches_requested"] is not True:
            refusal(prefix, f"{prefix}: exact source missing or changed")
        if observation["clean"] is not True:
            refusal(prefix, f"{prefix}: checkout closure missing or unclean")
        return observation["sha"]

    def pytest_command(name):
        return [str(python), "-X", "utf8", "-B", "-m", "pytest", "-q", "--strict-markers",
                "-p", "pytest_timeout", "-p", "no:cacheprovider", "-c", "pyproject.toml",
                "-o", "addopts=", "--basetemp", str(work / name)]

    def plugin_options(mode, prefix):
        options = ["-p", PLUGIN, "--sl-partition-mode", mode,
                   "--sl-partition-inventory", str(out / "inventory.json"),
                   "--sl-partition-evidence", str(out / prefix),
                   "--sl-partition-source-sha", expected, "--sl-partition-lock-sha", digest(lock)]
        if mode == "execute":
            options += ["--sl-partition-shard", shard]
        return options

    try:
        # Once pool identity and output location are established, every bounded
        # acquisition failure is a structured refusal with nullable unseen pins.
        specifications = (
            ("parameters", Path(os.environ["EC_WORKLOAD_PARAMETERS"])
             if os.environ.get("EC_WORKLOAD_PARAMETERS") else None, "parameters.raw.json", 4096),
            ("lock", ROOT / "uv.lock", "uv.lock.raw", MAX_JSON_BYTES),
            ("plugin", ROOT / "workloads/m12_adjudication_verify/pytest_partition.py",
             "partition-plugin.raw.py", MAX_JSON_BYTES),
        )
        received = {}
        for name, path, artifact, cap in specifications:
            try:
                received[name] = acquire_input(name, path, out, artifact, cap, acquisitions, budget)
            except (OSError, ValueError, BudgetExhausted) as exc:
                early_refusal = True
                refusal("acquisition-" + name, "fixed input acquisition refused: " + name, exc)
        raw_parameters = received.get("parameters")
        lock = received.get("lock")
        if "plugin" in received:
            plugin_sha = digest(received["plugin"])
        if raw_parameters is not None:
            try:
                shard = parameters(raw_parameters)
                acquisitions["parameters"]["semantic_validated"] = True
            except (ValueError, UnicodeError) as exc:
                early_refusal = True
                acquisitions["parameters"]["semantic_validated"] = False
                acquisitions["parameters"]["error_type"] = type(exc).__name__
                refusal("parameters", "required exact shard parameter refused", exc)
        if lock is not None:
            try:
                requirements = locked_requirements(lock)
                acquisitions["lock"]["semantic_validated"] = True
            except (ValueError, KeyError, TypeError) as exc:
                early_refusal = True
                acquisitions["lock"]["semantic_validated"] = False
                acquisitions["lock"]["error_type"] = type(exc).__name__
                refusal("dependency-lock", "original eight-wheel lock refused", exc)
        actual = source_check("initial")
        if not problems:
            raw_requirements = ("\n".join(requirements) + "\n").encode("utf-8")
            write_new(work / "requirements.txt", raw_requirements)
            write_new(out / "requirements.txt", raw_requirements)
        python = work / "venv" / "Scripts" / "python.exe"
        if not problems and runner.run("venv", [sys.executable, "-I", "-B", "-m", "venv",
                                               str(work / "venv")], 60):
            problems.append("isolated venv creation failed")
        if not problems and runner.run("dependencies", [str(python), "-I", "-B", "-m", "pip",
                "install", "--isolated", "--disable-pip-version-check", "--no-cache-dir", "--no-deps",
                "--require-hashes", "--only-binary=:all:", "-r", str(work / "requirements.txt")], 240):
            problems.append("original hash-pinned dependency installation failed")
        if not problems:
            code = runner.run("focused", pytest_command("focused") + ["--junitxml",
                              str(out / "focused.xml"), "-p",
                              "workloads.m12_adjudication_verify.pytest_outcome_guard",
                              "--sl-outcome-evidence", str(out / "focused"), *FOCUSED], 300)
            try:
                suites["focused"] = focused_result(out / "focused.xml", code,
                    read_bounded(out / "focused.session.json", MAX_JSON_BYTES),
                    read_bounded(out / "focused.events.jsonl", MAX_EVENTS_BYTES))
            except (OSError, ValueError, ET.ParseError) as exc:
                refusal("focused", "focused raw outcomes or genuine JUnit refused", exc)
            # A diagnostic failure can still yield a fresh partition observation.
            # A timeout or exhausted budget starts no further test subprocess.
            if runner.steps[-1]["timed_out"] or runner.steps[-1].get("budget_exhausted"):
                raise BudgetExhausted("focused did not close within the entry budget")
            code = runner.run("collection", pytest_command("collection") + plugin_options(
                              "collect", "collection") + ["--collect-only", "tests"], 120)
            raw_inventory = read_bounded(out / "inventory.json", MAX_JSON_BYTES)
            value = collection_result(raw_inventory, read_bounded(out / "collection.session.json",
                                      MAX_JSON_BYTES), read_bounded(out / "collection.events.jsonl",
                                      MAX_EVENTS_BYTES), code=code, source_sha=expected,
                                      lock_sha=digest(lock), plugin_sha=plugin_sha)
            suites["collection"] = {"tests": len(value["items"]), "inventory_sha256": digest(raw_inventory)}
            code = runner.run("partition", pytest_command("partition") + plugin_options(
                              "execute", "partition") + ["--junitxml", str(out / "partition.xml"),
                              "tests"], 1600)
            suites["partition"] = partition_result(raw_inventory,
                read_bounded(out / "partition.assignment.json", MAX_JSON_BYTES),
                read_bounded(out / "partition.events.jsonl", MAX_EVENTS_BYTES),
                read_bounded(out / "partition.session.json", MAX_JSON_BYTES),
                read_bounded(out / "partition.xml", MAX_JUNIT_BYTES), shard=shard, code=code)
    except (OSError, ValueError, KeyError, TypeError, ET.ParseError, BudgetExhausted) as exc:
        refusal("entry", "partition evidence incomplete", exc)
    try:
        source_check("final", final=True)
    except (OSError, ValueError, UnicodeError, BudgetExhausted) as exc:
        refusal("final-source", "final source closure incomplete", exc)
    ready = not problems and "partition" in suites and budget.remaining() > 0
    if budget.remaining() <= 0:
        problems.append("entry deadline exhausted before result finalization")
    result = {
        "schema_version": 1, "scope": "partition_only", "partition_complete": False,
        "phase_checks_complete": ready, "early_refusal": early_refusal,
        "full_windows_verdict": "NOT_ESTABLISHED", "shard": shard,
        "parameters_sha256": digest(raw_parameters) if raw_parameters is not None else None,
        "requested_sha": expected, "actual_sha": actual,
        "host": host, "runtime": {"python": sys.version, "platform": platform.platform()},
        "uv_lock_sha256": digest(lock) if lock is not None else None,
        "plugin_sha256": plugin_sha, "requirements": requirements,
        "acquisitions": acquisitions, "source_observations": source_observations,
        "steps": runner.steps, "suites": suites, "problems": problems, "errors": errors,
        "entry_budget": {"seconds": ENTRY_SECONDS, "finalization_reserve": FINALIZATION_RESERVE,
                         "remaining_seconds": round(budget.remaining(), 3),
                         "origin": "entry invocation, after EC preparation"},
        "limitations": [
            "Partition completion requires the terminal raw-digest predicate and actual wrapper exit zero/elapsed<=1800; internal result alone is insufficient.",
            "One fixed partition only; full Windows requires four fresh same-source receipts and identity reconciliation.",
            "Hash partitions do not guarantee equal duration or fit; no retry or cap extension.",
            "Entry budget does not authenticate job-start time or guarantee outer 35-minute publication headroom.",
            "Native process creation and synchronous file IO have no interruptible deadline guarantee; outer EC job remains hard bounded.",
            "Timeout logs are partial; descendant closure may be unconfirmed and never establishes completion.",
            "No formal W3 execution, case verdict, runner adoption, release or security attestation.",
        ],
    }
    return finalize(out, result, budget)
