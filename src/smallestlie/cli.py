"""SmallestLie CLI."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from smallestlie import __version__
from smallestlie.attacks.catalog import load_catalog
from smallestlie.campaign.batch import load_batch_config, run_batch
from smallestlie.campaign.nightly import run_nightly
from smallestlie.campaign.runner import run_campaign
from smallestlie.ci.baseline import compare_to_baseline, load_summary
from smallestlie.ci.diff_select import (
    filter_catalog_file,
    load_changed_paths,
    select_attacks_for_diff,
)
from smallestlie.ci.gate import CiGateConfig, run_ci_gate
from smallestlie.ledger.verify import verify_ledger
from smallestlie.meters.suite import run_measurement_suite
from smallestlie.models import ExitCode
from smallestlie.policy.authorization import (
    AuthorizationError,
    default_fixture_authorization,
    load_authorization,
    validate_authorization,
)
from smallestlie.sandbox.executor import scrub_environment
from smallestlie.sandbox.workspace import inventory_digest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="smallestlie",
        description="Authorized adversarial repository verification harness",
    )
    parser.add_argument("--version", action="version", version=f"smallestlie {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("doctor", help="Check local harness health")

    p_auth = sub.add_parser("authorize", help="Validate an authorization file")
    p_auth.add_argument("--config", required=True, help="Path to authorization YAML")

    p_cat = sub.add_parser("catalog", help="Attack catalog operations")
    cat_sub = p_cat.add_subparsers(dest="catalog_cmd", required=True)
    p_cat_list = cat_sub.add_parser("list", help="List attacks in a catalog")
    p_cat_list.add_argument("--catalog", default="catalogs/canonical-m1.yaml")
    p_cat_show = cat_sub.add_parser("show", help="Show one attack from catalog")
    p_cat_show.add_argument("attack_id")
    p_cat_show.add_argument("--catalog", default="catalogs/canonical-m1.yaml")

    p_run = sub.add_parser("campaign", help="Campaign operations")
    camp_sub = p_run.add_subparsers(dest="campaign_cmd", required=True)
    p_camp_run = camp_sub.add_parser("run", help="Run a campaign")
    p_camp_run.add_argument("--target", required=True)
    p_camp_run.add_argument("--catalog", default="catalogs/canonical-m1.yaml")
    p_camp_run.add_argument("--seed", type=int, default=49314)
    p_camp_run.add_argument("--adapter", default="fixture_gate")
    p_camp_run.add_argument("--authorization", default=None)
    p_camp_run.add_argument("--output", default="outputs")
    p_camp_run.add_argument("--keep-workspaces", action="store_true")
    p_camp_run.add_argument(
        "--plan-mode",
        choices=["single", "pairwise", "mixed"],
        default=None,
        help="Override catalog plan mode (single|pairwise|mixed)",
    )
    p_camp_run.add_argument(
        "--diff-file",
        default=None,
        help="git diff --name-only file; filter catalog by trust-surface families",
    )

    p_batch = camp_sub.add_parser(
        "batch",
        help="Run campaigns for multiple authorized local targets from a batch YAML",
    )
    p_batch.add_argument("--config", required=True, help="Batch YAML config path")
    p_batch.add_argument("--diff-file", default=None, help="Optional shared diff filter")
    p_batch.add_argument("--budget-seconds", type=int, default=None)

    p_replay = sub.add_parser("replay", help="Replay a witness directory")
    p_replay.add_argument("witness_dir")
    p_replay.add_argument("--target", default=None, help="Override fixture path")
    p_replay.add_argument("--attempts", type=int, default=3)

    p_min = sub.add_parser("minimize", help="Re-minimize mutations for a run directory")
    p_min.add_argument("run_dir", help="Path to campaign runs/<run-id>")
    p_min.add_argument("--target", required=True)
    p_min.add_argument("--adapter", default="fixture_gate")
    p_min.add_argument("--attempts", type=int, default=3)

    p_ledger = sub.add_parser("ledger", help="Ledger operations")
    led_sub = p_ledger.add_subparsers(dest="ledger_cmd", required=True)
    p_led_v = led_sub.add_parser("verify", help="Verify campaign ledger")
    p_led_v.add_argument("campaign_dir")

    p_report = sub.add_parser("report", help="Print campaign summary path / status")
    p_report.add_argument("campaign_dir")

    p_inspect = sub.add_parser("inspect-target", help="Inspect a local target")
    p_inspect.add_argument("--target", required=True)
    p_inspect.add_argument("--adapter", default="fixture_gate")

    p_ci = sub.add_parser("ci-gate", help="Offline CI gate (synthetic fixtures; honest status)")
    p_ci.add_argument("--budget-seconds", type=int, default=600)
    p_ci.add_argument("--output", default="outputs/ci")
    p_ci.add_argument("--artifact-dir", default="artifacts/smallestlie")
    p_ci.add_argument("--diff-file", default=None, help="git diff --name-only file")
    p_ci.add_argument("--baseline", default=None, help="Prior ci-summary.json for comparison")
    p_ci.add_argument("--seed", type=int, default=49314)
    p_ci.add_argument(
        "--full",
        action="store_true",
        help="Use full M1 catalog for naive; honest uses full-no-vrf (VRF contract)",
    )

    p_bc = sub.add_parser("baseline-compare", help="Compare two campaign/ci summaries")
    p_bc.add_argument("--current", required=True)
    p_bc.add_argument("--baseline", required=True)

    p_measure = sub.add_parser(
        "measure",
        help="Run measurement suite (meter first; trust claims only if meters pass)",
    )
    p_measure.add_argument(
        "--campaign",
        default=None,
        help="Optional campaign dir to meter (false-accept yield, replay, etc.)",
    )
    p_measure.add_argument("--output", default="outputs/measurements")

    p_bs = sub.add_parser(
        "blindspots",
        help="Print blind-spot queue from latest or fresh measurement report",
    )
    p_bs.add_argument("--report", default=None, help="measurement-report.json path")
    p_bs.add_argument("--output", default="outputs/measurements")
    p_bs.add_argument("--refresh", action="store_true", help="Re-run measure first")

    p_nightly = sub.add_parser(
        "nightly",
        help="Auto-campaign all known synthetic fixtures (for cron / schedule)",
    )
    p_nightly.add_argument("--budget-seconds", type=int, default=7200)
    p_nightly.add_argument("--output", default="outputs/nightly")
    p_nightly.add_argument("--seed", type=int, default=49314)

    p_sel = sub.add_parser(
        "select-attacks",
        help="Preview diff-aware attack selection (no execution)",
    )
    p_sel.add_argument("--catalog", default="catalogs/canonical-m1.yaml")
    p_sel.add_argument("--diff-file", default=None)
    p_sel.add_argument("--diff-text", default=None)
    p_sel.add_argument("--path", action="append", default=None, help="Changed path (repeatable)")

    args = parser.parse_args(argv)
    root = _project_root()

    if args.command == "doctor":
        return cmd_doctor(root)
    if args.command == "authorize":
        return cmd_authorize(args.config)
    if args.command == "catalog":
        return cmd_catalog(args, root)
    if args.command == "campaign" and args.campaign_cmd == "run":
        return cmd_campaign_run(args, root)
    if args.command == "campaign" and args.campaign_cmd == "batch":
        return cmd_campaign_batch(args, root)
    if args.command == "replay":
        return cmd_replay(args, root)
    if args.command == "minimize":
        return cmd_minimize(args, root)
    if args.command == "ledger" and args.ledger_cmd == "verify":
        return cmd_ledger_verify(args.campaign_dir)
    if args.command == "report":
        return cmd_report(args.campaign_dir)
    if args.command == "inspect-target":
        return cmd_inspect(args, root)
    if args.command == "ci-gate":
        return cmd_ci_gate(args, root)
    if args.command == "baseline-compare":
        return cmd_baseline_compare(args)
    if args.command == "measure":
        return cmd_measure(args, root)
    if args.command == "blindspots":
        return cmd_blindspots(args, root)
    if args.command == "nightly":
        return cmd_nightly(args, root)
    if args.command == "select-attacks":
        return cmd_select_attacks(args, root)
    print(f"unknown command: {args.command}", file=sys.stderr)
    return int(ExitCode.INVALID_CONFIG)


def _project_root() -> Path:
    # Prefer cwd if it looks like the project; else package parents.
    cwd = Path.cwd()
    if (cwd / "pyproject.toml").is_file() and (cwd / "src" / "smallestlie").is_dir():
        return cwd
    # src/smallestlie/cli.py -> parents[2] = repo root
    here = Path(__file__).resolve()
    candidate = here.parents[2]
    if (candidate / "pyproject.toml").is_file():
        return candidate
    return cwd


def cmd_doctor(root: Path) -> int:
    checks: list[tuple[str, bool, str]] = []
    checks.append(("python>=3.12", sys.version_info >= (3, 12), sys.version.split()[0]))
    checks.append(("project_root", (root / "pyproject.toml").is_file(), str(root)))
    checks.append(
        ("attacks_dir", (root / "attacks").is_dir(), str(root / "attacks"))
    )
    checks.append(
        ("fixtures_naive", (root / "fixtures" / "naive_gate").is_dir(), "fixtures/naive_gate")
    )
    checks.append(
        ("fixtures_honest", (root / "fixtures" / "honest_gate").is_dir(), "fixtures/honest_gate")
    )
    checks.append(
        ("catalog_m1", (root / "catalogs" / "canonical-m1.yaml").is_file(), "catalogs/canonical-m1.yaml")
    )
    env = scrub_environment({"AWS_SECRET_ACCESS_KEY": "dummy", "PATH": "x", "SMALLESTLIE_TEST": "1"})
    checks.append(
        (
            "env_scrub_strips_secrets",
            "AWS_SECRET_ACCESS_KEY" not in env,
            "credential keys stripped",
        )
    )
    checks.append(("network_default_denied", env.get("SMALLESTLIE_NETWORK") == "denied", "denied"))

    ok = True
    print(f"smallestlie doctor v{__version__}")
    for name, passed, detail in checks:
        status = "OK" if passed else "FAIL"
        if not passed:
            ok = False
        print(f"  [{status}] {name}: {detail}")
    if ok:
        print("doctor: PASS")
        return 0
    print("doctor: FAIL")
    return int(ExitCode.HARNESS_ERROR)


def cmd_authorize(config: str) -> int:
    try:
        auth = load_authorization(config)
        target = validate_authorization(auth)
        print(json.dumps({"ok": True, "digest": auth.digest(), "target": str(target)}, indent=2))
        return 0
    except AuthorizationError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        return int(ExitCode.BLOCKED)


def cmd_catalog(args: Any, root: Path) -> int:
    catalog_path = Path(args.catalog)
    if not catalog_path.is_absolute():
        catalog_path = root / catalog_path
    catalog = load_catalog(catalog_path, attacks_root=root / "attacks")
    if args.catalog_cmd == "list":
        for aid in catalog.attack_ids:
            spec = catalog.attacks[aid]
            print(f"{aid}\t{spec.family}\t{spec.name}")
        return 0
    if args.catalog_cmd == "show":
        if args.attack_id not in catalog.attacks:
            print(f"not found: {args.attack_id}", file=sys.stderr)
            return int(ExitCode.INVALID_CONFIG)
        print(json.dumps(catalog.attacks[args.attack_id].to_dict(), indent=2, default=str))
        return 0
    return int(ExitCode.INVALID_CONFIG)


def cmd_campaign_run(args: Any, root: Path) -> int:
    catalog_path: str | Path = args.catalog
    diff_meta = None
    if args.diff_file:
        catalog_full = Path(args.catalog)
        if not catalog_full.is_absolute():
            catalog_full = root / catalog_full
        catalog = load_catalog(catalog_full, attacks_root=root / "attacks")
        changed = load_changed_paths(diff_file=args.diff_file)
        fam_map = {a.attack_id: a.family for a in catalog.ordered()}
        selection = select_attacks_for_diff(
            catalog.attack_ids,
            fam_map,
            changed_paths=changed,
            attack_specs={
                a.attack_id: {
                    "family": a.family,
                    "parents": (a.raw or {}).get("parents")
                    or (a.applies_when or {}).get("parent_attacks")
                    or [],
                }
                for a in catalog.ordered()
            },
        )
        diff_meta = selection
        if selection["mode"] in {"empty_after_diff", "unknown_diff"}:
            print(
                json.dumps(
                    {"error": f"diff selection blocked: {selection['mode']}", "diff": selection},
                    indent=2,
                )
            )
            return 4
        if selection["mode"] == "diff_filtered":
            out = Path(args.output)
            if not out.is_absolute():
                out = root / out
            out.mkdir(parents=True, exist_ok=True)
            catalog_path = filter_catalog_file(
                out / "catalog-diff-filtered.yaml",
                catalog,
                selection["selected_attack_ids"],
            )

    summary = run_campaign(
        target=args.target,
        catalog_path=catalog_path,
        output_root=args.output,
        seed=args.seed,
        adapter_name=args.adapter,
        authorization_path=args.authorization,
        project_root=root,
        keep_workspaces=args.keep_workspaces,
        plan_mode=args.plan_mode,
    )
    payload = {
        "campaign_id": summary.get("campaign_id"),
        "status": summary.get("status"),
        "exit_code": summary.get("exit_code"),
        "false_accept_count": summary.get("false_accept_count"),
        "campaign_dir": summary.get("campaign_dir"),
        "source_immutable": summary.get("source_immutable"),
        "ledger_ok": summary.get("ledger_ok"),
    }
    if diff_meta:
        payload["diff_selection"] = {
            "mode": diff_meta.get("mode"),
            "mapped_families": diff_meta.get("mapped_families"),
            "selected_count": len(diff_meta.get("selected_attack_ids") or []),
            "excluded_count": len(diff_meta.get("excluded_attack_ids") or []),
        }
    print(json.dumps(payload, indent=2))
    return int(summary.get("exit_code", ExitCode.HARNESS_ERROR))


def cmd_campaign_batch(args: Any, root: Path) -> int:
    cfg = load_batch_config(args.config)
    if args.budget_seconds is not None:
        cfg.budget_seconds = args.budget_seconds
    report = run_batch(project_root=root, config=cfg, diff_file=args.diff_file)
    print(
        json.dumps(
            {
                "batch_id": report.get("batch_id"),
                "projection": report.get("projection"),
                "exit_code": report.get("exit_code"),
                "budget_exceeded": report.get("budget_exceeded"),
                "elapsed_seconds": report.get("elapsed_seconds"),
                "items": [
                    {
                        "name": i.get("name"),
                        "ran": i.get("ran"),
                        "expectation_met": i.get("expectation_met"),
                        "false_accept_count": i.get("false_accept_count"),
                        "campaign_status": i.get("campaign_status"),
                    }
                    for i in (report.get("items") or [])
                ],
                "report_json": report.get("report_json"),
            },
            indent=2,
        )
    )
    return int(report.get("exit_code", 5))


def cmd_replay(args: Any, root: Path) -> int:
    import yaml
    from smallestlie.adapters.base import get_adapter
    from smallestlie.attacks.schema import parse_attack_spec
    from smallestlie.baseline.capture import capture_baseline
    from smallestlie.campaign.runner import _replay_false_accept
    from smallestlie.policy.authorization import default_fixture_authorization

    witness = Path(args.witness_dir)
    if not witness.is_absolute():
        witness = (Path.cwd() / witness).resolve()
    attack_path = witness / "minimized-attack.yaml"
    if not attack_path.is_file():
        print(f"missing minimized-attack.yaml in {witness}", file=sys.stderr)
        return int(ExitCode.INVALID_CONFIG)
    raw = yaml.safe_load(attack_path.read_text(encoding="utf-8"))
    attack = parse_attack_spec(raw, source_path=str(attack_path))

    manifest = {}
    man_path = witness / "evidence-manifest.json"
    if man_path.is_file():
        manifest = json.loads(man_path.read_text(encoding="utf-8"))

    fixture_name = manifest.get("source_fixture_name", "naive_gate")
    if args.target:
        target = Path(args.target)
        if not target.is_absolute():
            target = (root / target).resolve()
    else:
        target = (root / "fixtures" / fixture_name).resolve()

    adapter = get_adapter("fixture_gate")
    auth = default_fixture_authorization(target)
    baseline = capture_baseline(
        target,
        adapter_name=adapter.name,
        adapter_version=adapter.version,
        authorization_digest=auth.digest(),
    )
    replay = _replay_false_accept(
        attack=attack,
        target_path=target,
        baseline=baseline,
        adapter=adapter,
        allowlist=adapter.command_allowlist(),
        attempts=args.attempts,
    )
    out = witness / "replay-result.json"
    out.write_text(json.dumps(replay, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(replay, indent=2))
    if replay.get("stable"):
        return 0
    return int(ExitCode.HARNESS_ERROR)


def cmd_minimize(args: Any, root: Path) -> int:
    import yaml
    from smallestlie.adapters.base import get_adapter
    from smallestlie.attacks.schema import parse_attack_spec
    from smallestlie.baseline.capture import capture_baseline
    from smallestlie.campaign.runner import _run_mutant_once
    from smallestlie.minimize.ddmin import ddmin
    from smallestlie.models import ComparisonResult
    from smallestlie.policy.authorization import default_fixture_authorization

    run_dir = Path(args.run_dir)
    if not run_dir.is_absolute():
        run_dir = (Path.cwd() / run_dir).resolve()
    attack_path = run_dir / "attack.yaml"
    if not attack_path.is_file():
        print(f"missing attack.yaml in {run_dir}", file=sys.stderr)
        return int(ExitCode.INVALID_CONFIG)
    attack = parse_attack_spec(
        yaml.safe_load(attack_path.read_text(encoding="utf-8")),
        source_path=str(attack_path),
    )
    target = Path(args.target)
    if not target.is_absolute():
        target = (root / target).resolve()
    adapter = get_adapter(getattr(args, "adapter", None) or "fixture_gate")
    auth = default_fixture_authorization(target)
    baseline = capture_baseline(
        target,
        adapter_name=adapter.name,
        adapter_version=adapter.version,
        authorization_digest=auth.digest(),
    )

    def interesting(subset: list) -> bool:
        one = _run_mutant_once(
            mutations=subset,
            attack=attack,
            target_path=target,
            baseline=baseline,
            adapter=adapter,
            allowlist=adapter.command_allowlist(),
        )
        return (
            one.get("comparison", {}).get("result")
            == ComparisonResult.FALSE_ACCEPT_OBSERVED.value
        )

    result = ddmin(list(attack.mutations), interesting)
    out = run_dir / "minimization.json"
    out.write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result.to_dict(), indent=2, default=str))
    return 0


def cmd_ledger_verify(campaign_dir: str) -> int:
    path = Path(campaign_dir)
    ledger_path = path / "ledger.jsonl" if path.is_dir() else path
    result = verify_ledger(ledger_path)
    print(json.dumps(result, indent=2))
    return 0 if result.get("ok") else int(ExitCode.HARNESS_ERROR)


def cmd_report(campaign_dir: str) -> int:
    path = Path(campaign_dir)
    report = path / "campaign-report.json"
    if not report.is_file():
        print(f"missing {report}", file=sys.stderr)
        return int(ExitCode.INVALID_CONFIG)
    data = json.loads(report.read_text(encoding="utf-8"))
    print(json.dumps({
        "campaign_id": data.get("campaign_id"),
        "status": data.get("status"),
        "exit_code": data.get("exit_code"),
        "false_accept_count": data.get("false_accept_count"),
        "markdown": str(path / "campaign-report.md"),
    }, indent=2))
    return int(data.get("exit_code", 0))


def cmd_inspect(args: Any, root: Path) -> int:
    target = Path(args.target)
    if not target.is_absolute():
        target = (root / target).resolve()
    info = {
        "target": str(target),
        "exists": target.is_dir(),
        "digest": inventory_digest(target) if target.is_dir() else None,
        "adapter": args.adapter,
        "revision": None,
    }
    for name in ("REVISION", "revision.txt"):
        p = target / name
        if p.is_file():
            info["revision"] = p.read_text(encoding="utf-8").strip()
            break
    print(json.dumps(info, indent=2))
    return 0 if target.is_dir() else int(ExitCode.INVALID_CONFIG)


def cmd_ci_gate(args: Any, root: Path) -> int:
    from smallestlie.ci.gate import CiProfile

    # Full mode: naive gets VRF (FA expected on verifier sabotage); honest must
    # use no-VRF catalog so clean expectation remains sound.
    if args.full:
        naive_catalog = "catalogs/ci-offline-full.yaml"
        honest_catalog = "catalogs/ci-offline-full-no-vrf.yaml"
    else:
        naive_catalog = "catalogs/ci-offline-fast.yaml"
        honest_catalog = "catalogs/ci-offline-fast.yaml"
    profiles = [
        CiProfile(
            name="naive_expect_false_accept",
            target="fixtures/naive_gate",
            catalog=naive_catalog,
            expect="fail_false_accept",
            seed=args.seed,
        ),
        CiProfile(
            name="honest_expect_clean",
            target="fixtures/honest_gate",
            catalog=honest_catalog,
            expect="pass_no_false_accept",
            seed=args.seed,
        ),
    ]
    cfg = CiGateConfig(
        profiles=profiles,
        budget_seconds=args.budget_seconds,
        output_root=args.output,
        artifact_dir=args.artifact_dir,
        diff_file=args.diff_file,
        baseline_path=args.baseline,
        seed=args.seed,
    )
    summary = run_ci_gate(project_root=root, config=cfg, profiles=profiles)
    print(
        json.dumps(
            {
                "projection": summary.get("projection"),
                "exit_code": summary.get("exit_code"),
                "gha_conclusion": summary.get("gha_conclusion"),
                "budget_exceeded": summary.get("budget_exceeded"),
                "elapsed_seconds": summary.get("elapsed_seconds"),
                "profiles": [
                    {
                        "name": p.get("name"),
                        "expectation_met": p.get("expectation_met"),
                        "false_accept_count": p.get("false_accept_count"),
                        "projection": p.get("projection"),
                    }
                    for p in (summary.get("profiles") or [])
                ],
                "artifacts": (summary.get("artifacts") or {}).get("staging_dir"),
            },
            indent=2,
        )
    )
    return int(summary.get("exit_code", ExitCode.HARNESS_ERROR))


def cmd_baseline_compare(args: Any) -> int:
    current = load_summary(args.current)
    baseline = load_summary(args.baseline)
    result = compare_to_baseline(current, baseline)
    print(json.dumps(result, indent=2))
    return 0 if result.get("ok") else int(ExitCode.FALSE_ACCEPT)


def cmd_measure(args: Any, root: Path) -> int:
    report = run_measurement_suite(
        root,
        campaign_dir=args.campaign,
        output_dir=args.output,
    )
    s = report.get("summary") or {}
    print(
        json.dumps(
            {
                "suite_ok": s.get("suite_ok"),
                "exit_code": report.get("exit_code"),
                "MEASURED_PASS": s.get("MEASURED_PASS"),
                "MEASURED_FAIL": s.get("MEASURED_FAIL"),
                "MEASURED_WARN": s.get("MEASURED_WARN"),
                "NOT_MEASURED": s.get("NOT_MEASURED"),
                "claims_trusted": s.get("claims_trusted"),
                "claims_deferred": s.get("claims_deferred"),
                "claims_untrusted": s.get("claims_untrusted"),
                "blindspots": s.get("blindspots"),
                "blindspots_high": s.get("blindspots_high"),
                "report_json": report.get("report_json"),
                "report_md": report.get("report_md"),
            },
            indent=2,
        )
    )
    return int(report.get("exit_code", 5))


def cmd_nightly(args: Any, root: Path) -> int:
    report = run_nightly(
        project_root=root,
        budget_seconds=args.budget_seconds,
        output_root=args.output,
        seed=args.seed,
    )
    print(
        json.dumps(
            {
                "batch_id": report.get("batch_id"),
                "projection": report.get("projection"),
                "exit_code": report.get("exit_code"),
                "elapsed_seconds": report.get("elapsed_seconds"),
                "items": [
                    {
                        "name": i.get("name"),
                        "ran": i.get("ran"),
                        "expectation_met": i.get("expectation_met"),
                        "false_accept_count": i.get("false_accept_count"),
                    }
                    for i in (report.get("items") or [])
                ],
                "report_json": report.get("report_json"),
            },
            indent=2,
        )
    )
    return int(report.get("exit_code", 5))


def cmd_select_attacks(args: Any, root: Path) -> int:
    catalog_path = Path(args.catalog)
    if not catalog_path.is_absolute():
        catalog_path = root / catalog_path
    catalog = load_catalog(catalog_path, attacks_root=root / "attacks")
    changed = load_changed_paths(
        diff_file=args.diff_file,
        diff_text=args.diff_text,
        paths=args.path,
    )
    fam_map = {a.attack_id: a.family for a in catalog.ordered()}
    selection = select_attacks_for_diff(
        catalog.attack_ids,
        fam_map,
        changed_paths=changed,
        attack_specs={
            a.attack_id: {
                "family": a.family,
                "parents": (a.raw or {}).get("parents")
                or (a.applies_when or {}).get("parent_attacks")
                or [],
            }
            for a in catalog.ordered()
        },
    )
    print(json.dumps(selection, indent=2, sort_keys=True))
    if selection.get("mode") == "empty_after_diff":
        return 4
    return 0


def cmd_blindspots(args: Any, root: Path) -> int:
    report_path = Path(args.report) if args.report else None
    if args.refresh or report_path is None or not Path(report_path).is_file():
        out = args.output
        report = run_measurement_suite(root, output_dir=out)
        report_path = Path(report["report_json"])
    else:
        report = json.loads(Path(report_path).read_text(encoding="utf-8"))

    spots = report.get("blindspots") or []
    # severity filter print
    high = [s for s in spots if s.get("severity") == "high"]
    med = [s for s in spots if s.get("severity") == "medium"]
    low = [s for s in spots if s.get("severity") == "low"]
    print(
        json.dumps(
            {
                "report": str(report_path),
                "counts": {"high": len(high), "medium": len(med), "low": len(low)},
                "high": high,
                "medium": med,
                "low": low,
                "retest_queue": [
                    {
                        "id": s.get("spot_id"),
                        "severity": s.get("severity"),
                        "remediation": s.get("remediation"),
                    }
                    for s in spots
                ],
            },
            indent=2,
        )
    )
    # exit 2 if high blind spots remain
    return 2 if high else (3 if med else 0)
