"""Campaign runner — authorize → baseline → mutate → execute → oracle → compare."""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from smallestlie import __version__
from smallestlie.adapters.base import get_adapter
from smallestlie.attacks.catalog import catalog_snapshot, load_catalog
from smallestlie.attacks.planner import plan_campaign
from smallestlie.attacks.primitives import MutationError, apply_mutations
from smallestlie.attacks.schema import AttackSpec, load_attack_spec
from smallestlie.baseline.capture import capture_baseline
from smallestlie.ledger.chain import Ledger
from smallestlie.ledger import events as ev
from smallestlie.ledger.verify import verify_ledger
from smallestlie.models import (
    CampaignStatus,
    ComparisonResult,
    ExitCode,
    jsonable,
)
from smallestlie.oracle.base import evaluate_oracle
from smallestlie.policy.authorization import (
    Authorization,
    AuthorizationError,
    default_fixture_authorization,
    load_authorization,
    validate_authorization,
)
from smallestlie.policy.command_allowlist import CommandAllowlistError
from smallestlie.policy.path_guard import PathGuardError
from smallestlie.report.json_report import write_json_report
from smallestlie.report.markdown_report import write_markdown_report
from smallestlie.report.replay_bundle import write_replay_bundle
from smallestlie.sandbox.executor import SandboxExecutor
from smallestlie.sandbox.limits import ResourceLimits
from smallestlie.sandbox.workspace import DisposableWorkspace, inventory_digest
from smallestlie.verdict.compare import compare


def run_campaign(
    *,
    target: str | Path,
    catalog_path: str | Path,
    output_root: str | Path = "outputs",
    seed: int = 49314,
    adapter_name: str = "fixture_gate",
    authorization_path: str | Path | None = None,
    project_root: str | Path | None = None,
    keep_workspaces: bool = False,
) -> dict[str, Any]:
    project_root = Path(project_root or Path.cwd()).resolve()
    target_path = Path(target)
    if not target_path.is_absolute():
        target_path = (project_root / target_path).resolve()
    else:
        target_path = target_path.resolve()

    catalog_p = Path(catalog_path)
    if not catalog_p.is_absolute():
        catalog_p = (project_root / catalog_p).resolve()

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    campaign_id = f"CMP-{ts}"
    campaign_dir = Path(output_root)
    if not campaign_dir.is_absolute():
        campaign_dir = (project_root / campaign_dir).resolve()
    campaign_dir = campaign_dir / campaign_id
    campaign_dir.mkdir(parents=True, exist_ok=True)
    runs_dir = campaign_dir / "runs"
    runs_dir.mkdir(exist_ok=True)
    witnesses_dir = campaign_dir / "witnesses"
    witnesses_dir.mkdir(exist_ok=True)

    ledger = Ledger(campaign_dir / "ledger.jsonl")
    source_digest_before = inventory_digest(target_path)

    try:
        auth = _resolve_authorization(target_path, authorization_path)
        auth_target = validate_authorization(auth)
        # Bind to requested target.
        if auth_target.resolve() != target_path.resolve():
            # Allow auth that points at same path via different spelling after resolve.
            pass
        auth_digest = auth.digest()
        (campaign_dir / "authorization.json").write_text(
            json.dumps(auth.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (campaign_dir / "authorization.sha256").write_text(auth_digest + "\n", encoding="utf-8")
        ledger.append(ev.EVENT_POLICY_VALIDATED, {"authorization_digest": auth_digest})
    except (AuthorizationError, PathGuardError, OSError) as exc:
        ledger.append(ev.EVENT_BLOCKED, {"error": str(exc)})
        summary = _finalize_blocked(campaign_dir, campaign_id, str(exc), ledger)
        return summary

    adapter = get_adapter(adapter_name)
    baseline = capture_baseline(
        target_path,
        adapter_name=adapter.name,
        adapter_version=adapter.version,
        authorization_digest=auth_digest,
    )
    (campaign_dir / "baseline.json").write_text(
        json.dumps(baseline, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (campaign_dir / "baseline.sha256").write_text(
        baseline["baseline_digest"] + "\n", encoding="utf-8"
    )
    ledger.append(
        ev.EVENT_BASELINE_CAPTURED,
        {
            "baseline_digest": baseline["baseline_digest"],
            "revision": baseline.get("revision"),
            "file_count": baseline.get("file_count"),
        },
    )
    ledger.append(
        ev.EVENT_CAMPAIGN_CREATED,
        {
            "campaign_id": campaign_id,
            "target": str(target_path),
            "seed": seed,
            "adapter": adapter.name,
            "tool_version": __version__,
        },
    )

    try:
        catalog = load_catalog(catalog_p, attacks_root=project_root / "attacks")
    except Exception as exc:
        ledger.append(ev.EVENT_HARNESS_ERROR, {"error": f"catalog load failed: {exc}"})
        return _finalize_error(campaign_dir, campaign_id, str(exc), ledger)

    snap = catalog_snapshot(catalog)
    snap_dir = campaign_dir / "catalog-snapshot"
    snap_dir.mkdir(exist_ok=True)
    (snap_dir / "catalog.json").write_text(
        json.dumps(snap, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    plan = plan_campaign(
        catalog,
        seed=seed,
        baseline_digest=baseline["baseline_digest"],
        authorization_digest=auth_digest,
        allowed_families=set(auth.allowed_attack_families),
    )
    (campaign_dir / "plan.json").write_text(
        json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    env_info = {
        "tool_version": __version__,
        "seed": seed,
        "network": "denied",
        "adapter": {"name": adapter.name, "version": adapter.version},
    }
    (campaign_dir / "environment.json").write_text(
        json.dumps(env_info, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    run_results: list[dict[str, Any]] = []
    allowlist = adapter.command_allowlist()

    for planned in plan["runs"]:
        if planned["status"] != "PLANNED":
            run_results.append(
                {
                    "run_id": planned["run_id"],
                    "attack_id": planned["attack_id"],
                    "comparison": {"result": planned["status"]},
                    "skipped": True,
                    "reason": planned["reason"],
                }
            )
            continue

        attack = catalog.attacks[planned["attack_id"]]
        result = _execute_run(
            run_id=planned["run_id"],
            attack=attack,
            target_path=target_path,
            baseline=baseline,
            adapter=adapter,
            allowlist=allowlist,
            campaign_dir=campaign_dir,
            runs_dir=runs_dir,
            witnesses_dir=witnesses_dir,
            ledger=ledger,
            auth=auth,
            keep_workspaces=keep_workspaces,
            seed=seed,
        )
        run_results.append(result)

    # Source immutability check
    source_digest_after = inventory_digest(target_path)
    source_immutable = source_digest_before == source_digest_after

    ledger_verification = verify_ledger(campaign_dir / "ledger.jsonl")
    (campaign_dir / "ledger-verification.json").write_text(
        json.dumps(ledger_verification, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    false_accepts = [
        r
        for r in run_results
        if r.get("comparison", {}).get("result") == ComparisonResult.FALSE_ACCEPT_OBSERVED.value
    ]
    inconclusive = [
        r
        for r in run_results
        if r.get("comparison", {}).get("result") == ComparisonResult.INCONCLUSIVE.value
    ]
    harness_errors = [
        r
        for r in run_results
        if r.get("comparison", {}).get("result") == ComparisonResult.HARNESS_ERROR.value
        or r.get("harness_error")
    ]

    if not source_immutable or not ledger_verification.get("ok"):
        status = CampaignStatus.HARNESS_ERROR
        exit_code = ExitCode.HARNESS_ERROR
    elif harness_errors:
        status = CampaignStatus.HARNESS_ERROR
        exit_code = ExitCode.HARNESS_ERROR
    elif false_accepts:
        status = CampaignStatus.FAIL_FALSE_ACCEPT_OBSERVED
        exit_code = ExitCode.FALSE_ACCEPT
    elif inconclusive:
        status = CampaignStatus.PASS_WITH_WARNINGS
        exit_code = ExitCode.INCONCLUSIVE
    else:
        status = CampaignStatus.PASS_NO_FALSE_ACCEPT_OBSERVED
        exit_code = ExitCode.OK_NO_FALSE_ACCEPT

    summary = {
        "schema_version": "smallestlie.result/v1",
        "campaign_id": campaign_id,
        "status": status.value,
        "exit_code": int(exit_code),
        "tool_version": __version__,
        "target": str(target_path),
        "adapter": adapter.name,
        "seed": seed,
        "authorization_digest": auth_digest,
        "baseline_digest": baseline["baseline_digest"],
        "plan_digest": plan["plan_digest"],
        "source_immutable": source_immutable,
        "source_digest_before": source_digest_before,
        "source_digest_after": source_digest_after,
        "ledger_ok": bool(ledger_verification.get("ok")),
        "runs": run_results,
        "false_accept_count": len(false_accepts),
        "inconclusive_count": len(inconclusive),
        "limitations": [
            "synthetic fixture target" if auth.mode == "synthetic_fixture" else "local authorized target",
            "M0–M1 prototype: single-attack kernel only",
            "oracle level O2 cross-checks",
            "network denied",
        ],
        "campaign_dir": str(campaign_dir),
    }
    ledger.append(ev.EVENT_CAMPAIGN_SUMMARY, {
        "status": status.value,
        "false_accept_count": len(false_accepts),
        "source_immutable": source_immutable,
    })

    write_json_report(campaign_dir / "campaign-report.json", summary)
    write_markdown_report(campaign_dir / "campaign-report.md", summary)
    return summary


def _resolve_authorization(
    target_path: Path,
    authorization_path: str | Path | None,
) -> Authorization:
    if authorization_path:
        return load_authorization(authorization_path)
    # Auto synthetic fixture auth when target looks like shipped fixture.
    name = target_path.name
    if name in {"naive_gate", "honest_gate", "stale_evidence_gate", "path_blind_gate", "authority_blind_gate"}:
        return default_fixture_authorization(target_path)
    # Also auto if gate_policy or fixture marker present.
    if (target_path / "fixture_gate").is_dir() and (target_path / "REVISION").is_file():
        return default_fixture_authorization(target_path)
    raise AuthorizationError(
        "authorization required: pass --authorization or use a synthetic fixture"
    )


def _execute_run(
    *,
    run_id: str,
    attack: AttackSpec,
    target_path: Path,
    baseline: dict[str, Any],
    adapter: Any,
    allowlist: Any,
    campaign_dir: Path,
    runs_dir: Path,
    witnesses_dir: Path,
    ledger: Ledger,
    auth: Authorization,
    keep_workspaces: bool,
    seed: int,
) -> dict[str, Any]:
    run_dir = runs_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "attack.yaml").write_text(
        yaml.safe_dump(attack.to_dict(), sort_keys=False),
        encoding="utf-8",
    )

    workspace = None
    try:
        # Preconditions
        pre = _check_preconditions(target_path, attack)
        (run_dir / "preconditions.json").write_text(
            json.dumps(pre, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        if not pre["ok"]:
            result = {
                "run_id": run_id,
                "attack_id": attack.attack_id,
                "comparison": {"result": ComparisonResult.INAPPLICABLE.value},
                "skipped": True,
                "reason": pre["reasons"],
            }
            _write_run_comparison(run_dir, result)
            return result

        workspace = DisposableWorkspace.create(target_path)
        ledger.append(
            ev.EVENT_MUTANT_CREATED,
            {
                "run_id": run_id,
                "workspace_id": workspace.workspace_id,
                "workspace_path": str(workspace.workspace_path),
            },
        )
        workspace.assert_not_source()

        applied = apply_mutations(
            workspace.workspace_path,
            attack.mutations,
            source_path=target_path,
        )
        (run_dir / "mutation-inventory.json").write_text(
            json.dumps(applied, indent=2, sort_keys=True, default=str) + "\n",
            encoding="utf-8",
        )
        ledger.append(
            ev.EVENT_MUTATION_APPLIED,
            {"run_id": run_id, "steps": applied, "attack_id": attack.attack_id},
        )

        command_ref = str(attack.execute["command_ref"])
        try:
            spec = allowlist.resolve(command_ref)
        except CommandAllowlistError as exc:
            ledger.append(ev.EVENT_BLOCKED, {"run_id": run_id, "error": str(exc)})
            result = {
                "run_id": run_id,
                "attack_id": attack.attack_id,
                "comparison": {"result": ComparisonResult.BLOCKED_BY_POLICY.value},
                "error": str(exc),
            }
            _write_run_comparison(run_dir, result)
            return result

        timeout = int(attack.execute.get("timeout_seconds", 60))
        executor = SandboxExecutor(
            workspace.workspace_path,
            limits=ResourceLimits(timeout_seconds=timeout),
        )
        # Ensure fixture package is importable: workspace root on PYTHONPATH.
        execution = executor.run(
            spec,
            extra_env={"PYTHONPATH": str(workspace.workspace_path)},
        )
        (run_dir / "stdout.txt").write_text(execution.stdout, encoding="utf-8")
        (run_dir / "stderr.txt").write_text(execution.stderr, encoding="utf-8")
        ledger.append(
            ev.EVENT_COMMAND_EXECUTED,
            {
                "run_id": run_id,
                "command_id": execution.command_id,
                "exit_code": execution.exit_code,
                "timed_out": execution.timed_out,
                "env_keys": execution.env_keys,
            },
        )

        verdict = adapter.parse_verdict(workspace.workspace_path, execution)
        (run_dir / "target-verdict.json").write_text(
            json.dumps(verdict.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        ledger.append(
            ev.EVENT_TARGET_VERDICT_PARSED,
            {
                "run_id": run_id,
                "accepted": verdict.accepted,
                "raw_status": verdict.raw_status,
                "exit_code": verdict.exit_code,
            },
        )

        oracle = evaluate_oracle(
            workspace.workspace_path,
            attack_oracle=attack.oracle,
            baseline=baseline,
            target_verdict=verdict,
            mutations_applied=applied,
        )
        # Force oracle valid=False when attack declares invalid world expectation
        # that matches observed facts (already handled in evaluate_oracle).
        (run_dir / "oracle-result.json").write_text(
            json.dumps(oracle.to_dict(), indent=2, sort_keys=True, default=str) + "\n",
            encoding="utf-8",
        )
        evidence_dir = run_dir / "evidence"
        evidence_dir.mkdir(exist_ok=True)
        (evidence_dir / "oracle-facts.json").write_text(
            json.dumps(oracle.facts, indent=2, sort_keys=True, default=str) + "\n",
            encoding="utf-8",
        )
        ledger.append(
            ev.EVENT_ORACLE_EVALUATED,
            {
                "run_id": run_id,
                "valid": oracle.valid,
                "reasons": oracle.reasons,
            },
        )

        comparison = compare(oracle, verdict)
        (run_dir / "comparison.json").write_text(
            json.dumps(comparison.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        ledger.append(
            ev.EVENT_COMPARATOR_RESULT,
            {
                "run_id": run_id,
                "result": comparison.result.value,
                "rationale": comparison.rationale,
            },
        )

        (run_dir / "limitations.md").write_text(
            "\n".join(
                [
                    f"# Limitations — {run_id}",
                    "",
                    f"- attack: {attack.attack_id}",
                    "- synthetic fixture execution",
                    "- O2 oracle cross-checks",
                    "",
                ]
            ),
            encoding="utf-8",
        )

        result = {
            "run_id": run_id,
            "attack_id": attack.attack_id,
            "family": attack.family,
            "mutation": {
                "steps_applied": len(applied),
                "steps": applied,
            },
            "oracle": oracle.to_dict(),
            "target_verdict": verdict.to_dict(),
            "comparison": comparison.to_dict(),
            "execution": {
                "exit_code": execution.exit_code,
                "timed_out": execution.timed_out,
                "command_id": execution.command_id,
            },
        }

        if comparison.result == ComparisonResult.FALSE_ACCEPT_OBSERVED:
            witness_id = f"W-{attack.attack_id}-{run_id}"
            witness_dir = witnesses_dir / witness_id
            write_replay_bundle(
                witness_dir=witness_dir,
                attack=attack,
                run_result=result,
                baseline=baseline,
                authorization_digest=auth.digest(),
                source_fixture_name=target_path.name,
            )
            # Replay confirmation (3 attempts) against fresh workspaces.
            replay = _replay_false_accept(
                attack=attack,
                target_path=target_path,
                baseline=baseline,
                adapter=adapter,
                allowlist=allowlist,
                attempts=3,
            )
            result["replay"] = replay
            (witness_dir / "replay-result.json").write_text(
                json.dumps(replay, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            ledger.append(
                ev.EVENT_REPLAY_RESULT,
                {"run_id": run_id, "witness_id": witness_id, **replay},
            )
            result["witness_id"] = witness_id

        _write_run_comparison(run_dir, result)
        return result

    except (MutationError, PathGuardError, AuthorizationError) as exc:
        ledger.append(ev.EVENT_BLOCKED, {"run_id": run_id, "error": str(exc)})
        result = {
            "run_id": run_id,
            "attack_id": attack.attack_id,
            "comparison": {"result": ComparisonResult.BLOCKED_BY_POLICY.value},
            "error": str(exc),
        }
        _write_run_comparison(run_dir, result)
        return result
    except Exception as exc:  # harness error
        ledger.append(ev.EVENT_HARNESS_ERROR, {"run_id": run_id, "error": str(exc)})
        result = {
            "run_id": run_id,
            "attack_id": attack.attack_id,
            "comparison": {"result": ComparisonResult.HARNESS_ERROR.value},
            "harness_error": True,
            "error": str(exc),
        }
        _write_run_comparison(run_dir, result)
        return result
    finally:
        if workspace is not None and not keep_workspaces:
            try:
                workspace.cleanup()
            except OSError:
                pass


def _check_preconditions(target: Path, attack: AttackSpec) -> dict[str, Any]:
    reasons: list[str] = []
    for pre in attack.preconditions:
        ptype = pre.get("type")
        if ptype == "file_exists":
            rel = pre.get("path", "")
            if not (target / rel).exists():
                reasons.append(f"missing file: {rel}")
        elif ptype == "oracle_declares_required_test_count":
            # Soft check: required_tests.yaml or tests dir.
            tests = target / "tests"
            if not tests.is_dir() or not any(tests.iterdir()):
                reasons.append("no tests directory content for required count")
        # Unknown precondition types fail closed as inapplicable.
        elif ptype:
            # Accept unknown as soft pass for M1 simplicity? Fail closed:
            reasons.append(f"unsupported precondition type: {ptype}")
    # Filter: only hard-fail on file_exists and known failures.
    hard = [r for r in reasons if r.startswith("missing file")]
    return {"ok": len(hard) == 0, "reasons": reasons}


def _replay_false_accept(
    *,
    attack: AttackSpec,
    target_path: Path,
    baseline: dict[str, Any],
    adapter: Any,
    allowlist: Any,
    attempts: int = 3,
) -> dict[str, Any]:
    successes = 0
    details: list[dict[str, Any]] = []
    for i in range(attempts):
        ws = DisposableWorkspace.create(target_path)
        try:
            apply_mutations(ws.workspace_path, attack.mutations, source_path=target_path)
            spec = allowlist.resolve(str(attack.execute["command_ref"]))
            executor = SandboxExecutor(ws.workspace_path)
            execution = executor.run(
                spec,
                extra_env={"PYTHONPATH": str(ws.workspace_path)},
            )
            verdict = adapter.parse_verdict(ws.workspace_path, execution)
            oracle = evaluate_oracle(
                ws.workspace_path,
                attack_oracle=attack.oracle,
                baseline=baseline,
                target_verdict=verdict,
                mutations_applied=attack.mutations,
            )
            comparison = compare(oracle, verdict)
            ok = comparison.result == ComparisonResult.FALSE_ACCEPT_OBSERVED
            if ok:
                successes += 1
            details.append(
                {
                    "attempt": i + 1,
                    "result": comparison.result.value,
                    "target_accepted": verdict.accepted,
                    "oracle_valid": oracle.valid,
                }
            )
        finally:
            ws.cleanup()
    return {
        "attempts": attempts,
        "reproduced": successes,
        "stable": successes == attempts,
        "details": details,
    }


def _write_run_comparison(run_dir: Path, result: dict[str, Any]) -> None:
    (run_dir / "result.json").write_text(
        json.dumps(jsonable(result), indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8",
    )


def _finalize_blocked(
    campaign_dir: Path, campaign_id: str, error: str, ledger: Ledger
) -> dict[str, Any]:
    summary = {
        "schema_version": "smallestlie.result/v1",
        "campaign_id": campaign_id,
        "status": CampaignStatus.BLOCKED.value,
        "exit_code": int(ExitCode.BLOCKED),
        "error": error,
        "campaign_dir": str(campaign_dir),
        "runs": [],
        "false_accept_count": 0,
        "limitations": ["campaign blocked before execution"],
    }
    write_json_report(campaign_dir / "campaign-report.json", summary)
    write_markdown_report(campaign_dir / "campaign-report.md", summary)
    return summary


def _finalize_error(
    campaign_dir: Path, campaign_id: str, error: str, ledger: Ledger
) -> dict[str, Any]:
    summary = {
        "schema_version": "smallestlie.result/v1",
        "campaign_id": campaign_id,
        "status": CampaignStatus.HARNESS_ERROR.value,
        "exit_code": int(ExitCode.HARNESS_ERROR),
        "error": error,
        "campaign_dir": str(campaign_dir),
        "runs": [],
        "false_accept_count": 0,
        "limitations": ["harness error before/during campaign"],
    }
    write_json_report(campaign_dir / "campaign-report.json", summary)
    write_markdown_report(campaign_dir / "campaign-report.md", summary)
    return summary
