"""Containment surface meters (import-level + structural)."""

from __future__ import annotations

from pathlib import Path

from smallestlie.meters.models import Measurement, MeterVerdict
from smallestlie.policy.command_allowlist import CommandAllowlist, CommandAllowlistError
from smallestlie.policy.network_policy import NetworkPolicy, NetworkPolicyError
from smallestlie.policy.path_guard import PathGuard, PathGuardError
from smallestlie.sandbox.executor import scrub_environment


def measure_policy_surface(tmp_root: Path | None = None) -> Measurement:
    """
    Execute micro-measurements of containment primitives (not full pytest).
    """
    from tempfile import TemporaryDirectory

    results: dict[str, bool] = {}
    details: dict[str, str] = {}

    with TemporaryDirectory() as td:
        root = Path(td)
        (root / "inside").mkdir()
        guard = PathGuard(root)

        # path traversal
        try:
            guard.ensure_relative_inside("../escape")
            results["path_traversal_blocked"] = False
        except PathGuardError:
            results["path_traversal_blocked"] = True

        # source mutation refused
        try:
            guard.assert_not_source(root, root)
            results["source_inplace_blocked"] = False
        except PathGuardError:
            results["source_inplace_blocked"] = True

        # command allowlist
        al = CommandAllowlist.from_mapping(
            {"ok": {"argv": ["python", "-m", "fixture_gate", "verify"]}}
        )
        try:
            al.resolve("not_allowed")
            results["unapproved_command_blocked"] = False
        except CommandAllowlistError:
            results["unapproved_command_blocked"] = True

        # network default
        try:
            NetworkPolicy(mode="allowed")
            results["network_non_denied_rejected"] = False
        except NetworkPolicyError:
            results["network_non_denied_rejected"] = True
        results["network_denied_ok"] = NetworkPolicy(mode="denied").mode == "denied"

        # env scrub
        env = scrub_environment(
            {
                "PATH": "x",
                "AWS_SECRET_ACCESS_KEY": "dummy",
                "GITHUB_TOKEN": "ghp_x",
                "HTTP_PROXY": "http://x",
            }
        )
        results["scrub_strips_aws"] = "AWS_SECRET_ACCESS_KEY" not in env
        results["scrub_strips_github"] = "GITHUB_TOKEN" not in env
        results["scrub_strips_proxy"] = "HTTP_PROXY" not in env
        results["scrub_marks_network_denied"] = env.get("SMALLESTLIE_NETWORK") == "denied"

    failed = [k for k, v in results.items() if not v]
    verdict = MeterVerdict.MEASURED_PASS if not failed else MeterVerdict.MEASURED_FAIL
    return Measurement(
        meter_id="containment.policy_surface",
        name="Containment primitive micro-measurements",
        verdict=verdict,
        value=sum(1 for v in results.values() if v),
        unit="checks_passed",
        threshold={"all_true": True},
        evidence={"checks": results, "failed": failed, "details": details},
    )
