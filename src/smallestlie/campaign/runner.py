"""Campaign runner — authorize → baseline → mutate → execute → oracle → compare."""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from smallestlie import __version__
from smallestlie.adapters.base import EnginePinError, get_adapter
from smallestlie.attacks.catalog import catalog_snapshot, load_catalog
from smallestlie.attacks.composition import CompositionLimits
from smallestlie.attacks.planner import interaction_report, plan_campaign
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
from smallestlie.minimize.ddmin import ddmin
from smallestlie.report.json_report import write_json_report
from smallestlie.report.markdown_report import write_markdown_report
from smallestlie.report.regression import export_regression
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
    plan_mode: str | None = None,
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

    # Collision-proof: second + microseconds + short uuid (same-second campaigns
    # must never share an evidence directory).
    import uuid

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
    campaign_id = f"CMP-{ts}-{uuid.uuid4().hex[:8]}"
    campaign_dir = Path(output_root)
    if not campaign_dir.is_absolute():
        campaign_dir = (project_root / campaign_dir).resolve()
    campaign_dir = campaign_dir / campaign_id
    if campaign_dir.exists():
        # Extremely unlikely; still fail closed rather than merge evidence.
        campaign_id = f"CMP-{ts}-{uuid.uuid4().hex}"
        campaign_dir = campaign_dir.parent / campaign_id
    campaign_dir.mkdir(parents=True, exist_ok=False)
    runs_dir = campaign_dir / "runs"
    runs_dir.mkdir(exist_ok=True)
    witnesses_dir = campaign_dir / "witnesses"
    witnesses_dir.mkdir(exist_ok=True)

    ledger = Ledger(campaign_dir / "ledger.jsonl")
    source_digest_before = inventory_digest(target_path)

    try:
        auth = _resolve_authorization(target_path, authorization_path)
        auth_target = validate_authorization(auth)
        # Strict bind: authorization.target_path must resolve to the campaign target.
        if auth_target.resolve() != target_path.resolve():
            raise AuthorizationError(
                "authorization target mismatch: "
                f"auth={auth_target.resolve()} campaign={target_path.resolve()}"
            )
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

    mode = plan_mode or catalog.plan_mode or "single"
    limits = CompositionLimits(
        max_depth=int(catalog.composition_limits.get("max_depth", 2)),
        max_compound_runs=int(catalog.composition_limits.get("max_compound_runs", 32)),
        max_mutations_total=int(catalog.composition_limits.get("max_mutations_total", 16)),
        require_distinct_families=bool(
            catalog.composition_limits.get("require_distinct_families", False)
        ),
        require_distinct_ids=bool(
            catalog.composition_limits.get("require_distinct_ids", True)
        ),
    )
    # Declarative compounds: any catalog attack with family composition
    declared = [a for a in catalog.ordered() if a.family == "composition"]
    # Parent singles only for planning base set when mixed
    plan = plan_campaign(
        catalog,
        seed=seed,
        baseline_digest=baseline["baseline_digest"],
        authorization_digest=auth_digest,
        allowed_families=set(auth.allowed_attack_families),
        mode=mode,  # type: ignore[arg-type]
        composition_limits=limits,
        pairwise_allowlist=catalog.composition_pairs or None,
        compound_specs=declared if mode in ("mixed", "pairwise") else None,
    )
    composed_registry: dict[str, AttackSpec] = dict(plan.pop("_composed_specs", {}) or {})
    # Also register declared composition attacks
    for a in declared:
        composed_registry[a.attack_id] = a
    plan_for_disk = {k: v for k, v in plan.items() if not k.startswith("_")}
    (campaign_dir / "plan.json").write_text(
        json.dumps(plan_for_disk, indent=2, sort_keys=True) + "\n", encoding="utf-8"
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
    # Deduplicate plan runs by attack_id (declared + pairwise may overlap)
    seen_attack_ids: set[str] = set()

    for planned in plan["runs"]:
        aid = planned["attack_id"]
        if aid in seen_attack_ids and planned.get("kind") != "single":
            # Skip duplicate compound generation of same id
            continue
        seen_attack_ids.add(aid)

        if planned["status"] != "PLANNED":
            run_results.append(
                {
                    "run_id": planned["run_id"],
                    "attack_id": planned["attack_id"],
                    "kind": planned.get("kind", "single"),
                    "comparison": {"result": planned["status"]},
                    "skipped": True,
                    "reason": planned["reason"],
                }
            )
            continue

        if planned["attack_id"] in catalog.attacks:
            attack = catalog.attacks[planned["attack_id"]]
        elif planned["attack_id"] in composed_registry:
            attack = composed_registry[planned["attack_id"]]
        else:
            run_results.append(
                {
                    "run_id": planned["run_id"],
                    "attack_id": planned["attack_id"],
                    "comparison": {"result": ComparisonResult.HARNESS_ERROR.value},
                    "harness_error": True,
                    "error": f"attack not found: {planned['attack_id']}",
                }
            )
            continue

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
        result["kind"] = planned.get("kind", "single")
        result["parents"] = planned.get("parents")
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
        "plan_digest": plan.get("plan_digest"),
        "plan_mode": mode,
        "source_immutable": source_immutable,
        "source_digest_before": source_digest_before,
        "source_digest_after": source_digest_after,
        "ledger_ok": bool(ledger_verification.get("ok")),
        "runs": run_results,
        "false_accept_count": len(false_accepts),
        "inconclusive_count": len(inconclusive),
        "limitations": [
            "synthetic fixture target" if auth.mode == "synthetic_fixture" else "local authorized target",
            "M1–M4: singles + compound planner + minimize + O2/O3 oracles",
            f"plan_mode={mode}",
            "network denied",
        ],
        "campaign_dir": str(campaign_dir),
    }
    ix = interaction_report(plan_for_disk, run_results)
    summary["interaction"] = ix
    (campaign_dir / "interaction-report.json").write_text(
        json.dumps(ix, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    ledger.append(ev.EVENT_CAMPAIGN_SUMMARY, {
        "status": status.value,
        "false_accept_count": len(false_accepts),
        "source_immutable": source_immutable,
        "compound_only_false_accepts": len(ix.get("compound_only_false_accepts") or []),
        "plan_truncated": bool(ix.get("plan_truncated")),
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
    if name in {
        "naive_gate",
        "honest_gate",
        "stale_evidence_gate",
        "path_blind_gate",
        "authority_blind_gate",
        "composition_blind_gate",
        "greenwash_naive",
        "greenwash_honest",
        "checkwash_target",
        "checkwash_blind",
    }:
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

        # Adapter hook: materialize workspace shape git cannot express in a
        # copied tree (e.g. the git range a diff-based SUT reads).
        prep = adapter.prepare_workspace(workspace.workspace_path)
        if prep:
            ledger.append(ev.EVENT_MUTANT_CREATED, {"run_id": run_id, "prepared": prep})

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

        # Adapter hook: finalize the mutated workspace before execution
        # (e.g. commit the mutant so HEAD~1..HEAD exists).
        adapter.before_execute(workspace.workspace_path)

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
                    "- O2/O3 oracle cross-checks (never target verdict as truth)",
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
            required_replays = int(
                (attack.minimization or {}).get("required_replays", 3)
            )
            do_minimize = bool((attack.minimization or {}).get("remove_steps", True))

            minimal_mutations = list(attack.mutations)
            minimize_info: dict[str, Any] = {
                "original_steps": len(attack.mutations),
                "minimal_steps": len(attack.mutations),
                "skipped": not do_minimize or len(attack.mutations) <= 1,
            }
            if do_minimize and len(attack.mutations) > 1:

                def _interesting(subset: list[dict[str, Any]]) -> bool:
                    one = _run_mutant_once(
                        mutations=subset,
                        attack=attack,
                        target_path=target_path,
                        baseline=baseline,
                        adapter=adapter,
                        allowlist=allowlist,
                    )
                    return (
                        one.get("comparison", {}).get("result")
                        == ComparisonResult.FALSE_ACCEPT_OBSERVED.value
                    )

                min_result = ddmin(list(attack.mutations), _interesting)
                minimal_mutations = min_result.minimal_mutations
                minimize_info = min_result.to_dict()
                ledger.append(
                    ev.EVENT_COMPARATOR_RESULT,
                    {
                        "run_id": run_id,
                        "event": "minimization",
                        **{k: v for k, v in minimize_info.items() if k != "minimal_mutations"},
                        "minimal_steps": minimize_info.get("minimal_steps"),
                    },
                )

            result["minimization"] = minimize_info
            result["minimal_mutations"] = minimal_mutations

            # Build minimized attack view for witness
            min_attack_raw = dict(attack.to_dict())
            min_attack_raw["mutations"] = minimal_mutations
            from smallestlie.attacks.schema import parse_attack_spec

            min_attack = parse_attack_spec(min_attack_raw, source_path=attack.source_path)

            witness_id = f"W-{attack.attack_id}-{run_id}"
            witness_dir = witnesses_dir / witness_id
            write_replay_bundle(
                witness_dir=witness_dir,
                attack=min_attack,
                run_result=result,
                baseline=baseline,
                authorization_digest=auth.digest(),
                source_fixture_name=target_path.name,
            )
            (witness_dir / "minimized.patch.json").write_text(
                json.dumps(minimal_mutations, indent=2, sort_keys=True, default=str)
                + "\n",
                encoding="utf-8",
            )

            replay = _replay_false_accept(
                attack=min_attack,
                target_path=target_path,
                baseline=baseline,
                adapter=adapter,
                allowlist=allowlist,
                attempts=required_replays,
                mutations=minimal_mutations,
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

            if replay.get("stable"):
                reg = export_regression(
                    regressions_dir=campaign_dir / "regressions",
                    attack=min_attack,
                    minimal_mutations=minimal_mutations,
                    run_result=result,
                    campaign_id=campaign_dir.name,
                )
                result["regression"] = reg
                ledger.append(
                    ev.EVENT_REGRESSION_EXPORT,
                    {"run_id": run_id, **reg},
                )

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
    except EnginePinError as exc:
        ledger.append(ev.EVENT_BLOCKED, {"run_id": run_id, "error": str(exc)})
        result = {
            "run_id": run_id,
            "attack_id": attack.attack_id,
            "comparison": {"result": ComparisonResult.BLOCKED_BY_POLICY.value},
            "error": f"engine pin: {exc}",
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
    """Fail closed: unsupported preconditions block execution (no mutant run)."""
    reasons: list[str] = []
    for pre in attack.preconditions:
        ptype = pre.get("type")
        if ptype == "file_exists":
            rel = pre.get("path", "")
            if not (target / rel).exists():
                reasons.append(f"missing file: {rel}")
        elif ptype == "oracle_declares_required_test_count":
            tests = target / "tests"
            if not tests.is_dir() or not any(tests.iterdir()):
                reasons.append("no tests directory content for required count")
        elif ptype:
            # Unsupported types: hard block — never execute the attack.
            reasons.append(f"unsupported precondition type: {ptype}")
        else:
            reasons.append("precondition missing type")
    hard = [
        r
        for r in reasons
        if r.startswith("missing file")
        or r.startswith("unsupported precondition")
        or r.startswith("precondition missing")
        or r.startswith("no tests directory")
    ]
    return {"ok": len(hard) == 0, "reasons": reasons}


def _run_mutant_once(
    *,
    mutations: list[dict[str, Any]],
    attack: AttackSpec,
    target_path: Path,
    baseline: dict[str, Any],
    adapter: Any,
    allowlist: Any,
) -> dict[str, Any]:
    ws = DisposableWorkspace.create(target_path)
    try:
        adapter.prepare_workspace(ws.workspace_path)
        applied = apply_mutations(ws.workspace_path, mutations, source_path=target_path)
        adapter.before_execute(ws.workspace_path)
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
            mutations_applied=applied,
        )
        comparison = compare(oracle, verdict)
        return {
            "comparison": comparison.to_dict(),
            "target_accepted": verdict.accepted,
            "oracle_valid": oracle.valid,
            "exit_code": execution.exit_code,
        }
    finally:
        ws.cleanup()


def _replay_false_accept(
    *,
    attack: AttackSpec,
    target_path: Path,
    baseline: dict[str, Any],
    adapter: Any,
    allowlist: Any,
    attempts: int = 3,
    mutations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    muts = mutations if mutations is not None else list(attack.mutations)
    successes = 0
    details: list[dict[str, Any]] = []
    for i in range(attempts):
        one = _run_mutant_once(
            mutations=muts,
            attack=attack,
            target_path=target_path,
            baseline=baseline,
            adapter=adapter,
            allowlist=allowlist,
        )
        ok = one.get("comparison", {}).get("result") == ComparisonResult.FALSE_ACCEPT_OBSERVED.value
        if ok:
            successes += 1
        details.append(
            {
                "attempt": i + 1,
                "result": one.get("comparison", {}).get("result"),
                "target_accepted": one.get("target_accepted"),
                "oracle_valid": one.get("oracle_valid"),
            }
        )
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
