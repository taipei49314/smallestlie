"""Unit tests: checkwash adapters, git materialization, git-diff oracle."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from smallestlie.adapters.base import EnginePinError, get_adapter
from smallestlie.adapters.checkwash import (
    CheckwashAdapter,
    CheckwashBlindAdapter,
    engine_path,
    materialize_baseline,
    materialize_mutant,
    verify_engine_pin,
)
from smallestlie.models import TargetVerdict
from smallestlie.models import ComparisonResult, OracleResult
from smallestlie.oracle import git_diff
from smallestlie.oracle.base import evaluate_oracle
from smallestlie.sandbox.executor import ExecutionResult
from smallestlie.verdict.compare import compare

ROOT = Path(__file__).resolve().parents[2]


def _mini_target(tmp_path: Path) -> Path:
    target = tmp_path / "t"
    (target / "src").mkdir(parents=True)
    (target / "src" / "app.py").write_text("def total(xs):\n    return sum(xs)\n", encoding="utf-8")
    (target / "tests").mkdir()
    (target / "tests" / "test_app.py").write_text(
        "from src.app import total\n\ndef test_total():\n    assert total([1, 2]) == 3\n",
        encoding="utf-8",
    )
    return target


def _execution(exit_code: int, stdout: str = "", stderr: str = "") -> ExecutionResult:
    return ExecutionResult(
        command_id="run_checkwash_check",
        argv=[],
        cwd=".",
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
    )


class TestRegistry:
    def test_registry_exposes_checkwash_adapters(self) -> None:
        assert isinstance(get_adapter("checkwash"), CheckwashAdapter)
        assert isinstance(get_adapter("checkwash_blind"), CheckwashBlindAdapter)

    def test_allowlist_has_single_pinned_command(self) -> None:
        al = CheckwashAdapter().command_allowlist()
        assert al.ids() == ["run_checkwash_check"]
        spec = al.resolve("run_checkwash_check")
        assert list(spec.argv[1:]) == [
            str(engine_path()),
            "check",
            "HEAD~1..HEAD",
            "--format",
            "json",
        ]

    def test_blind_allowlist_shares_command_id(self) -> None:
        al = CheckwashBlindAdapter().command_allowlist()
        spec = al.resolve("run_checkwash_check")
        assert list(spec.argv[1:3]) == ["blind_check.py", "check"]


class TestEnginePin:
    def test_vendored_engine_matches_pin(self) -> None:
        # The repo ships the pinned artifact; if this fails the vendored file
        # or the pin constant drifted — both must move together.
        path = verify_engine_pin()
        assert path.name == "checkwash.pyz"

    def test_pin_mismatch_blocks(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        bogus = tmp_path / "not-checkwash.pyz"
        bogus.write_bytes(b"definitely not the engine")
        monkeypatch.setenv("CHECKWASH_PYZ", str(bogus))
        with pytest.raises(EnginePinError):
            verify_engine_pin()

    def test_missing_engine_blocks(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CHECKWASH_PYZ", str(tmp_path / "absent.pyz"))
        with pytest.raises(EnginePinError):
            verify_engine_pin()


class TestGitMaterialization:
    def test_deterministic_commits_across_workspaces(
        self, tmp_path: Path
    ) -> None:
        target = _mini_target(tmp_path)
        heads = []
        for _ in range(2):
            ws = tmp_path / f"ws{len(heads)}"
            ws.mkdir()
            (ws / "src").mkdir(parents=True)
            (ws / "tests").mkdir()
            for rel in ("src/app.py", "tests/test_app.py"):
                (ws / rel).write_text((target / rel).read_text(encoding="utf-8"), encoding="utf-8")
            base = materialize_baseline(ws)
            (ws / "tests" / "test_app.py").write_text(
                "from src.app import total\n\ndef test_total():\n    assert total([1, 2]) > 0\n",
                encoding="utf-8",
            )
            mut = materialize_mutant(ws)
            heads.append((base["baseline_commit"], mut["mutant_commit"], tuple(mut["changed_files"])))
        assert heads[0] == heads[1]
        assert heads[0][2] == ("tests/test_app.py",)

    def test_git_diff_oracle_facts(self, tmp_path: Path) -> None:
        target = _mini_target(tmp_path)
        ws = tmp_path / "ws"
        ws.mkdir()
        for rel in ("src/app.py", "tests/test_app.py"):
            dest = ws / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text((target / rel).read_text(encoding="utf-8"), encoding="utf-8")
        materialize_baseline(ws)
        facts_before = git_diff.evaluate(ws)["facts"]
        assert facts_before["diff_present"] is False

        (ws / "tests" / "test_app.py").write_text(
            "from src.app import total\n\ndef test_total():\n    assert total([1, 2]) > 0\n",
            encoding="utf-8",
        )
        materialize_mutant(ws)
        facts_after = git_diff.evaluate(ws)["facts"]
        assert facts_after["diff_present"] is True
        assert facts_after["changed_files"] == ["tests/test_app.py"]

    def test_git_diff_oracle_non_repo(self, tmp_path: Path) -> None:
        assert git_diff.evaluate(tmp_path)["facts"]["git_repo"] is False


class TestOracleDispatch:
    def _baseline_stub(self) -> dict:
        return {"baseline_digest": "x", "files": {}}

    def test_theater_declared_and_materialized_is_invalid(self, tmp_path: Path) -> None:
        target = _mini_target(tmp_path)
        ws = tmp_path / "ws"
        ws.mkdir()
        for rel in ("src/app.py", "tests/test_app.py"):
            dest = ws / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text((target / rel).read_text(encoding="utf-8"), encoding="utf-8")
        materialize_baseline(ws)
        (ws / "tests" / "test_app.py").write_text(
            "from src.app import total\n\ndef test_total():\n    assert total([1, 2]) > 0\n",
            encoding="utf-8",
        )
        materialize_mutant(ws)
        res = evaluate_oracle(
            ws,
            attack_oracle={
                "type": "git_diff_theater",
                "expected": {"no_theater": False, "paths": ["tests/test_app.py"]},
            },
            baseline=self._baseline_stub(),
            mutations_applied=[],
        )
        assert res.valid is False
        assert any("declared_theater_materialized" in r for r in res.reasons)

    def test_honest_world_no_oracle_surface_touch_is_valid(self, tmp_path: Path) -> None:
        target = _mini_target(tmp_path)
        ws = tmp_path / "ws"
        ws.mkdir()
        for rel in ("src/app.py", "tests/test_app.py"):
            dest = ws / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text((target / rel).read_text(encoding="utf-8"), encoding="utf-8")
        materialize_baseline(ws)
        (ws / "src" / "app.py").write_text(
            "def total(xs):\n    return sum(xs) or 0\n", encoding="utf-8"
        )
        materialize_mutant(ws)
        res = evaluate_oracle(
            ws,
            attack_oracle={
                "type": "git_diff_theater",
                "expected": {"no_theater": True, "paths": ["src/app.py"], "forbidden": ["tests/"]},
            },
            baseline=self._baseline_stub(),
            mutations_applied=[],
        )
        assert res.valid is True

    def test_engine_error_is_inconclusive_not_rejected(self) -> None:
        verdict = TargetVerdict(
            accepted=False, raw_status="engine_error", exit_code=2
        )
        res = evaluate_oracle(
            Path("."),
            attack_oracle={"type": "git_diff_theater", "expected": {"no_theater": False}},
            baseline=self._baseline_stub(),
            target_verdict=verdict,
            mutations_applied=[],
        )
        assert res.valid is None


class TestParseVerdict:
    PAYLOAD = json.dumps(
        {
            "checkwash_findings_version": 2,
            "run": {"base": "HEAD~1", "head": "HEAD", "checkwash_version": "0.4.2"},
            "findings": [],
            "summary": {"critical": 0, "high": 0, "warn": 0, "info": 0},
            "skipped_files": [],
            "config_errors": [],
            "verdict": "pass",
        },
        indent=2,
    )

    def test_exit0_pass_is_accepted(self) -> None:
        v = CheckwashAdapter().parse_verdict(Path("."), _execution(0, self.PAYLOAD))
        assert v.accepted is True
        assert v.raw_status == "pass"
        assert v.raw["checkwash_version"] == "0.4.2"
        assert v.execution_error is None

    def test_exit1_block_is_rejected(self) -> None:
        payload = self.PAYLOAD.replace('"pass"', '"block"')
        v = CheckwashAdapter().parse_verdict(Path("."), _execution(1, payload))
        assert v.accepted is False
        assert v.raw_status == "block"

    def test_exit2_is_engine_error_never_defense(self) -> None:
        v = CheckwashAdapter().parse_verdict(
            Path("."), _execution(2, "", stderr="Traceback ...")
        )
        assert v.accepted is False
        assert v.raw_status == "engine_error"
        assert v.warnings
        assert v.execution_error == "unexpected_exit_code:2"

    def test_multiline_json_payload_parses(self) -> None:
        v = CheckwashAdapter().parse_verdict(Path("."), _execution(0, self.PAYLOAD))
        assert v.accepted is True

    @pytest.mark.parametrize("exit_code", [0, 1])
    @pytest.mark.parametrize("output", ["", "{", "[]", "null", "banner\n{}", "{}\n{}",
                                       '{"verdict":"pass","verdict":"block"}', '{"x":NaN}',
                                       "[" * 2000 + "0" + "]" * 2000])
    def test_unusable_json_is_inconclusive(self, exit_code: int, output: str) -> None:
        v = CheckwashAdapter().read_verdict(Path("."), _execution(exit_code, output))
        assert v.execution_error == "invalid_findings_json"
        assert compare(OracleResult(valid=False), v).result == ComparisonResult.INCONCLUSIVE

    @pytest.mark.parametrize("exit_code", [0, 1])
    @pytest.mark.parametrize("key,value", [
        ("checkwash_findings_version", 1), ("checkwash_findings_version", True),
        ("run", []), ("run", {"base": "HEAD~1", "head": "HEAD", "checkwash_version": "dev"}),
        ("run", {"base": "", "head": "HEAD", "checkwash_version": "0.4.2"}),
        ("findings", {}), ("findings", [{"severity": "high"}]), ("findings", [False]),
        ("summary", {"critical": False, "high": 0, "warn": 0, "info": 0}),
        ("summary", {"critical": 0, "high": 1, "warn": 0, "info": 0}),
        ("skipped_files", "src/app.py"), ("config_errors", [False]), ("verdict", "ok"),
    ])
    def test_wrong_contract_is_inconclusive(self, exit_code: int, key: str, value: object) -> None:
        payload = json.loads(self.PAYLOAD)
        payload[key] = value
        v = CheckwashAdapter().read_verdict(Path("."), _execution(exit_code, json.dumps(payload)))
        assert v.execution_error is not None
        assert compare(OracleResult(valid=False), v).target_accepted is None

    @pytest.mark.parametrize("key", ["checkwash_findings_version", "run", "findings", "summary",
                                     "skipped_files", "config_errors", "verdict"])
    def test_missing_required_field_is_inconclusive(self, key: str) -> None:
        payload = json.loads(self.PAYLOAD)
        del payload[key]
        v = CheckwashAdapter().read_verdict(Path("."), _execution(1, json.dumps(payload)))
        assert v.execution_error is not None

    def test_findings_and_config_warnings_do_not_recompute_engine_policy(self) -> None:
        payload = json.loads(self.PAYLOAD)
        payload["findings"] = [{"rule": "EXAMPLE", "severity": "warn", "message": "warning",
                                "path": "tests/test_app.py", "unit": None, "fingerprint": "example",
                                "allowlisted": False}]
        payload["summary"]["warn"] = 1
        payload["config_errors"] = ["configuration warning"]
        v = CheckwashAdapter().read_verdict(Path("."), _execution(0, json.dumps(payload)))
        assert v.execution_error is None
        assert v.accepted is True
        assert "config_errors_present" in v.warnings

    @pytest.mark.parametrize("exit_code,report", [(0, "block"), (1, "pass")])
    def test_valid_channel_disagreement_is_preserved(self, exit_code: int, report: str) -> None:
        payload = json.loads(self.PAYLOAD)
        payload["verdict"] = report
        v = CheckwashAdapter().read_verdict(Path("."), _execution(exit_code, json.dumps(payload)))
        assert v.execution_error is None
        assert v.accepted is (exit_code == 0)
        assert v.channels["report_accepted"] is (report == "pass")
        assert v.channels["exit_accepted"] is (exit_code == 0)

    def test_blind_control_has_its_own_contract(self) -> None:
        payload = json.loads(self.PAYLOAD)
        payload["checkwash_findings_version"] = 1
        payload["run"]["checkwash_version"] = "blind-control"
        output = json.dumps(payload)
        blind = CheckwashBlindAdapter().read_verdict(Path("."), _execution(0, output))
        assert blind.execution_error is None
        assert blind.accepted is True
        real = CheckwashAdapter().read_verdict(Path("."), _execution(0, output))
        assert real.execution_error is not None
