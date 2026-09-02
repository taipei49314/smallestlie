"""Adapters for the real checkwash engine and its blind positive control.

checkwash (v0.2.9, vendored at ``verifiers/checkwash.pyz``) reads a **git
range**, not a directory of artifacts — so these adapters materialize the
disposable workspace into a deterministic git repository:

    copy fixture tree → git init → baseline commit (fixed identity+dates)
    → mutations land → mutant commit (fixed identity+dates)
    → ``checkwash check HEAD~1..HEAD --format json`` inside the workspace

Fixed committer identity and timestamps make commits byte-stable: same seed,
same SHAs, same diff, same verdict (checkwash SPEC §8 does its part; the
fixed dates do ours).

The blind variant runs a workspace-shipped stand-in that always prints a
clean verdict — the positive control proving this harness can observe a
false acceptance when the engine under test is lying-clean (mirrors the
``greenwash_naive`` pattern for the real-engine line).
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any

from smallestlie.adapters.base import Adapter, EnginePinError
from smallestlie.models import TargetVerdict
from smallestlie.policy.command_allowlist import CommandAllowlist
from smallestlie.sandbox.executor import ExecutionResult

PINNED_VERSION = "0.2.9"
PINNED_SHA256 = "b0928a112d063206465e423cf0c084f1e02d19d7ddb69e2914a45456fa58f198"
ENGINE_FILENAME = "checkwash.pyz"

# Fixed campaign identity: deterministic commit SHAs across machines/replays.
_COMMIT_NAME = "smallestlie-campaign"
_COMMIT_EMAIL = "campaign@smallestlie.local"
_BASELINE_DATE = "2025-01-01T00:00:00+00:00"
_MUTANT_DATE = "2025-01-01T00:00:01+00:00"


def engine_path() -> Path:
    """Resolve the pinned engine artifact.

    ``CHECKWASH_PYZ`` (harness-side env; never reaches the sandbox) overrides
    the vendored copy for machine-local experiments — the pin still applies.
    """
    env = os.environ.get("CHECKWASH_PYZ")
    if env:
        return Path(env)
    return Path(__file__).resolve().parents[3] / "verifiers" / ENGINE_FILENAME


def verify_engine_pin() -> Path:
    path = engine_path()
    if not path.is_file():
        raise EnginePinError(f"engine artifact missing: {path}")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != PINNED_SHA256:
        raise EnginePinError(
            f"engine pin mismatch for {path}: got {digest}, want {PINNED_SHA256}"
        )
    return path


def _git_env() -> dict[str, str]:
    # Minimal env; GIT_* context from the host must never leak in.
    keep = ("PATH", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT")
    env = {k: os.environ[k] for k in keep if k in os.environ}
    return env


def _git(workspace: Path, *args: str) -> str:
    proc = subprocess.run(
        [
            "git",
            "-c", f"user.name={_COMMIT_NAME}",
            "-c", f"user.email={_COMMIT_EMAIL}",
            "-c", "commit.gpgsign=false",
            "-c", "core.autocrlf=false",
            *args,
        ],
        cwd=str(workspace),
        env=_git_env(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if proc.returncode != 0:
        raise EnginePinError(f"git {' '.join(args[:2])} failed: {proc.stderr.strip()[:400]}")
    return proc.stdout


def materialize_baseline(workspace: Path) -> dict[str, Any]:
    """Turn the copied fixture tree into commit 0 of a deterministic repo."""
    _git(workspace, "init", "-q", "-b", "main")
    _git(workspace, "add", "-A")
    env = _git_env()
    env.update(
        {
            "GIT_AUTHOR_DATE": _BASELINE_DATE,
            "GIT_COMMITTER_DATE": _BASELINE_DATE,
        }
    )
    proc = subprocess.run(
        [
            "git",
            "-c", f"user.name={_COMMIT_NAME}",
            "-c", f"user.email={_COMMIT_EMAIL}",
            "-c", "commit.gpgsign=false",
            "commit",
            "-q",
            "-m", "smallestlie baseline",
        ],
        cwd=str(workspace),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if proc.returncode != 0:
        raise EnginePinError(f"baseline commit failed: {proc.stderr.strip()[:400]}")
    return {"baseline_commit": _git(workspace, "rev-parse", "HEAD").strip()}


def materialize_mutant(workspace: Path) -> dict[str, Any]:
    """Commit the applied mutations as HEAD so a range diff exists."""
    _git(workspace, "add", "-A")
    env = _git_env()
    env.update(
        {
            "GIT_AUTHOR_DATE": _MUTANT_DATE,
            "GIT_COMMITTER_DATE": _MUTANT_DATE,
        }
    )
    proc = subprocess.run(
        [
            "git",
            "-c", f"user.name={_COMMIT_NAME}",
            "-c", f"user.email={_COMMIT_EMAIL}",
            "-c", "commit.gpgsign=false",
            "commit",
            "-q",
            "-m", "smallestlie mutant",
        ],
        cwd=str(workspace),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    # An all-clean mutant commit is still a commit; only real git failures block.
    if proc.returncode != 0 and "nothing to commit" not in proc.stdout + proc.stderr:
        raise EnginePinError(f"mutant commit failed: {proc.stderr.strip()[:400]}")
    head = _git(workspace, "rev-parse", "HEAD").strip()
    changed = [
        line.strip()
        for line in _git(workspace, "diff", "--name-only", "HEAD~1..HEAD").splitlines()
        if line.strip()
    ]
    return {"mutant_commit": head, "changed_files": changed}


def _parse_findings_json(stdout: str) -> dict[str, Any]:
    text = (stdout or "").strip()
    if not text:
        return {}
    try:
        loaded = json.loads(text)
        return loaded if isinstance(loaded, dict) else {}
    except json.JSONDecodeError:
        # Tolerate leading banner lines; take outermost {...} block.
        start, end = text.find("{"), text.rfind("}")
        if start >= 0 and end > start:
            try:
                loaded = json.loads(text[start : end + 1])
                return loaded if isinstance(loaded, dict) else {}
            except json.JSONDecodeError:
                return {}
        return {}


class CheckwashAdapter(Adapter):
    name = "checkwash"
    version = "0.1.0"

    def command_allowlist(self) -> CommandAllowlist:
        engine = str(engine_path())
        return CommandAllowlist.from_mapping(
            {
                "run_checkwash_check": {
                    # Zero runtime deps (engine D-001): the pinned zipapp is the
                    # whole verifier; ${PYTHON} is the harness interpreter (3.12+,
                    # engine requires >=3.11).
                    "argv": [
                        "${PYTHON}",
                        engine,
                        "check",
                        "HEAD~1..HEAD",
                        "--format",
                        "json",
                    ],
                    "cwd": ".",
                    "timeout_seconds": 120,
                },
            }
        )

    def capabilities(self) -> list[str]:
        return [
            "target_verdict",
            "git_diff_verifier",
            "findings_json",
            "offline_audit",
            "deterministic_verdict",
        ]

    def prepare_workspace(self, workspace: Path) -> dict[str, Any]:
        pin = verify_engine_pin()
        info = materialize_baseline(workspace)
        return {"engine": str(pin), "engine_sha256": PINNED_SHA256, **info}

    def before_execute(self, workspace: Path) -> dict[str, Any]:
        return materialize_mutant(workspace)

    def parse_verdict(self, workspace: Path, execution: ExecutionResult) -> TargetVerdict:
        payload = _parse_findings_json(execution.stdout)
        verdict = str(payload.get("verdict", ""))
        summary = payload.get("summary") or {}
        warnings: list[str] = []
        if execution.timed_out:
            warnings.append("engine_timeout")
        if payload.get("config_errors"):
            warnings.append("config_errors_present")

        if execution.exit_code == 0:
            accepted = True
            raw_status = verdict or "pass"
        elif execution.exit_code == 1:
            accepted = False
            raw_status = verdict or "block"
        else:
            # SPEC §9: exit 2 = engine error — never a defense, never an acceptance.
            accepted = False
            raw_status = "engine_error"
            warnings.append((execution.stderr or "").strip()[:400])

        return TargetVerdict(
            accepted=accepted,
            raw_status=raw_status,
            exit_code=execution.exit_code,
            warnings=warnings,
            raw={
                "checkwash_version": payload.get("run", {}).get("checkwash_version"),
                "summary": summary,
                "skipped_files": payload.get("skipped_files", []),
            },
            evidence_refs=["stdout.txt"],
        )


class CheckwashBlindAdapter(CheckwashAdapter):
    """Positive control: a stand-in engine that always accepts, on purpose."""

    name = "checkwash_blind"
    version = "0.1.0"

    def command_allowlist(self) -> CommandAllowlist:
        return CommandAllowlist.from_mapping(
            {
                # Same command id as the real adapter — the attack YAML stays
                # identical; the adapter decides which engine answers it.
                "run_checkwash_check": {
                    "argv": [
                        "${PYTHON}",
                        "blind_check.py",
                        "check",
                        "HEAD~1..HEAD",
                        "--json",
                    ],
                    "cwd": ".",
                    "timeout_seconds": 60,
                },
            }
        )

    def capabilities(self) -> list[str]:
        return [
            "target_verdict",
            "git_diff_verifier",
            "offline_audit",
            "deliberately_blind_positive_control",
        ]

    def prepare_workspace(self, workspace: Path) -> dict[str, Any]:
        # No engine pin: the blind stand-in ships inside the fixture itself.
        if not (workspace / "blind_check.py").is_file():
            raise EnginePinError("blind_check.py missing from fixture workspace")
        return materialize_baseline(workspace)
