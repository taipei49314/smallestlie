"""Bounded exact-source regression on the human-authorized EC pool host."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import time
import tomllib
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[2]
HOST = "LAPTOP-50KP71KA"
DEPENDENCIES = {
    "pytest", "pytest-timeout", "pyyaml", "colorama", "iniconfig", "packaging", "pluggy", "pygments"
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main(*, workload_name: str = "execution-verdict-verify",
         focused_paths: tuple[str, ...] | None = None,
         heading: str = "SmallestLie execution verdict regression",
         focused_timeout: int = 300,
         full_timeout: int = 1200) -> int:
    required = ("EC_WORKLOAD_SOURCE", "EC_WORKLOAD_OUT", "EC_WORKLOAD_WORK", "EC_WORKLOAD_SHA")
    if any(not os.environ.get(key) for key in required):
        raise RuntimeError("run only through the approved EC pool workload")
    if (os.environ.get("EC_WORKLOAD_REPOSITORY") != "taipei49314/smallestlie"
            or os.environ.get("EC_WORKLOAD_NAME") != workload_name
            or Path(os.environ["EC_WORKLOAD_SOURCE"]).resolve() != ROOT):
        raise RuntimeError("unexpected workload identity")
    host = platform.node().upper()
    if host != HOST or os.environ.get("COMPUTERNAME", "").upper() != HOST:
        raise RuntimeError(f"this regression requires {HOST}, observed {host}")
    if (sys.platform != "win32" or sys.version_info[:2] != (3, 12)
            or platform.machine().lower() not in {"amd64", "x86_64"}):
        raise RuntimeError("the approved dependency wheels require Python 3.12 Windows x64")
    expected = os.environ["EC_WORKLOAD_SHA"]
    if not re.fullmatch(r"[0-9a-f]{40}", expected):
        raise RuntimeError("an exact reviewed source SHA is required")
    out = Path(os.environ["EC_WORKLOAD_OUT"]).resolve()
    work = Path(os.environ["EC_WORKLOAD_WORK"]).resolve()
    out.mkdir(parents=True, exist_ok=True)
    work.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, PYTHONUTF8="1", PYTHONDONTWRITEBYTECODE="1",
               PYTHONPATH=os.pathsep.join((str(ROOT / "src"), str(ROOT / "fixtures"))),
               PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", PYTHONHASHSEED="49314")
    env.pop("PYTEST_ADDOPTS", None)
    env.pop("PYTEST_PLUGINS", None)
    steps: list[dict] = []
    problems: list[str] = []
    counts: dict[str, dict] = {}
    requirements: list[str] = []
    lock_bytes = (ROOT / "uv.lock").read_bytes()

    def run(name: str, command: list[str], timeout: int = 300) -> int:
        started = time.monotonic()
        timed_out = False
        try:
            process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                code = process.returncode
            except subprocess.TimeoutExpired as exc:
                code, timed_out = 124, True
                stdout, stderr = exc.stdout or b"", exc.stderr or b""
                # Kill only this recorded child PID and its descendants. A bare
                # parent kill can leave grandchildren holding the output pipes.
                taskkill = str(Path(os.environ["SystemRoot"]) / "System32" / "taskkill.exe")
                try:
                    killed = subprocess.run([taskkill, "/PID", str(process.pid), "/T", "/F"],
                                            capture_output=True, timeout=15, check=False,
                                            creationflags=subprocess.CREATE_NO_WINDOW)
                    if killed.returncode and process.poll() is None:
                        process.kill()
                except (OSError, subprocess.TimeoutExpired):
                    if process.poll() is None:
                        process.kill()
                try:
                    stdout, stderr = process.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    stderr += b"\nTimed-out descendant output pipes could not be drained.\n"
        except OSError as exc:
            code, stdout, stderr = 2, b"", str(exc).encode("utf-8")
        (out / f"{name}.stdout").write_bytes(stdout)
        (out / f"{name}.stderr").write_bytes(stderr)
        steps.append({"name": name, "command": command, "exit_code": code,
                      "elapsed_seconds": round(time.monotonic() - started, 3), "timed_out": timed_out,
                      "stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr)})
        return code

    def source_check(prefix: str) -> str:
        code = run(f"{prefix}-source", ["git", "rev-parse", "--verify", "HEAD"], 15)
        actual = (out / f"{prefix}-source.stdout").read_text(encoding="ascii").strip()
        if code or actual != expected:
            problems.append(f"{prefix}: source SHA mismatch or unreadable source")
        code = run(f"{prefix}-status", ["git", "status", "--porcelain", "-z"], 15)
        if code or (out / f"{prefix}-status.stdout").read_bytes():
            problems.append(f"{prefix}: source checkout is not clean")
        return actual

    actual = source_check("initial")
    if not problems:
        try:
            packages = tomllib.loads(lock_bytes.decode("utf-8"))["package"]
            selected = [p for p in packages if p["name"] in DEPENDENCIES]
            if {p["name"] for p in selected} != DEPENDENCIES or len(selected) != len(DEPENDENCIES):
                raise ValueError("lock must contain exactly the eight expected dependency packages")
            for package in sorted(selected, key=lambda p: p["name"]):
                suffix = "-cp312-cp312-win_amd64.whl" if package["name"] == "pyyaml" else "-none-any.whl"
                wheels = [w for w in package["wheels"] if w["url"].endswith(suffix)]
                if len(wheels) != 1:
                    raise ValueError(f"expected one compatible wheel for {package['name']}")
                wheel = wheels[0]
                if (not wheel["url"].startswith("https://files.pythonhosted.org/packages/")
                        or not re.fullmatch(r"sha256:[0-9a-f]{64}", wheel["hash"])):
                    raise ValueError("unexpected wheel host or hash")
                requirements.append(f"{package['name']} @ {wheel['url']} --hash={wheel['hash']}")
            req = work / "requirements.txt"
            req.write_text("\n".join(requirements) + "\n", encoding="utf-8", newline="\n")
            (out / "requirements.txt").write_bytes(req.read_bytes())
        except (OSError, ValueError, KeyError, TypeError) as exc:
            problems.append(f"dependency lock invalid: {exc}")

    python = work / "venv" / "Scripts" / "python.exe"
    if not problems and run("venv", [sys.executable, "-I", "-B", "-m", "venv", str(work / "venv")], 60):
        problems.append("isolated venv creation failed")
    if not problems and run("dependencies", [str(python), "-I", "-B", "-m", "pip", "install",
            "--isolated", "--disable-pip-version-check", "--no-cache-dir", "--no-deps",
            "--require-hashes", "--only-binary=:all:", "-r", str(work / "requirements.txt")], 240):
        problems.append("hash-pinned dependency installation failed")

    if not problems:
        phases = [
            ("focused", focused_timeout, list(focused_paths) if focused_paths is not None else ["tests/unit/test_execution_verdict.py",
                              "tests/unit/test_execution_binding.py", "tests/unit/test_checkwash_adapter.py",
                              "tests/integration/test_execution_failures.py", "tests/unit/test_comparator.py"]),
            ("full", full_timeout, ["tests"]),
        ]
        for name, timeout, paths in phases:
            command = [str(python), "-X", "utf8", "-B", "-m", "pytest", "-q", "--strict-markers",
                       "-p", "pytest_timeout", "-p", "no:cacheprovider", "--basetemp", str(work / name),
                       "--junitxml", str(out / f"{name}.xml"), *paths]
            code = run(name, command, timeout)
            try:
                cases = ET.parse(out / f"{name}.xml").getroot().findall(".//testcase")
                counts[name] = {"tests": len(cases),
                                "failures": sum(c.find("failure") is not None for c in cases),
                                "errors": sum(c.find("error") is not None for c in cases),
                                "skipped": sum(c.find("skipped") is not None for c in cases)}
                if not cases or any(counts[name][k] for k in ("failures", "errors", "skipped")):
                    problems.append(f"{name}: zero tests, failures, errors or skips")
            except (OSError, ET.ParseError) as exc:
                problems.append(f"{name}: JUnit missing or unreadable: {exc}")
            if code:
                problems.append(f"{name}: nonzero exit {code}")
            # Preserve a full-suite observation even if the focused phase found a regression.
            # A timeout stops further testing; the outer EC Job Object also kills
            # all remaining descendants when this entry exits.
            if steps[-1]["timed_out"]:
                break

    source_check("final")
    result = {"schema_version": 1, "requested_sha": expected, "actual_sha": actual, "host": host,
              "runtime": {"python": sys.version, "platform": platform.platform()},
              "uv_lock_sha256": digest(lock_bytes), "requirements": requirements,
              "steps": steps, "suites": counts, "passed": not problems, "problems": problems,
              "limitations": ["one EC Windows Python 3.12 runtime; no cross-OS claim",
                              "existing known false accepts remain expected regression observations",
                              "not a product acceptance, new attack evaluation, release or security attestation"]}
    (out / "result.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n",
                                     encoding="utf-8", newline="\n")
    lines = [f"# {heading}", "", f"Result: {'FAIL' if problems else 'PASS'}",
             f"Source: `{actual}` (requested `{expected}`)", f"Host: `{host}`", f"Suites: {counts}", "",
             "Evidence: result.json, focused.xml, full.xml and raw stdout/stderr logs.", ""]
    lines += [f"- {problem}" for problem in problems]
    lines += ["", *[f"- Limit: {item}" for item in result["limitations"]], ""]
    (out / "SUMMARY.md").write_text("\n".join(lines), encoding="utf-8", newline="\n")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
