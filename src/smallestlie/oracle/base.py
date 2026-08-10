"""Independent ground-truth oracle orchestration (never uses target verdict as truth)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from smallestlie.models import OracleResult, TargetVerdict
from smallestlie.oracle import (
    discovery,
    policy_presence,
    protected_identity,
    report_exit,
    revision_binding,
)


def evaluate_oracle(
    workspace: Path,
    *,
    attack_oracle: dict[str, Any],
    baseline: dict[str, Any],
    target_verdict: TargetVerdict | None = None,
    mutations_applied: list[dict[str, Any]] | None = None,
) -> OracleResult:
    """
    Evaluate independent oracles.

    Note: target_verdict is accepted only for *consistency* plugins that compare
    channels on the target output; it is never used as ground-truth validity.
    """
    otype = str(attack_oracle.get("type", "composite"))
    expected = dict(attack_oracle.get("expected") or {})
    plugins_cfg = list(attack_oracle.get("plugins") or [])

    plugin_results: dict[str, Any] = {}
    reasons: list[str] = []
    evidence: list[str] = []
    facts: dict[str, Any] = {}

    # Always collect structural facts.
    disc = discovery.evaluate(workspace)
    plugin_results["discovery"] = disc
    facts.update({f"discovery.{k}": v for k, v in disc["facts"].items()})

    rev = revision_binding.evaluate(workspace, baseline=baseline)
    plugin_results["revision_binding"] = rev
    facts.update({f"revision.{k}": v for k, v in rev["facts"].items()})

    pol = policy_presence.evaluate(workspace)
    plugin_results["policy_presence"] = pol
    facts.update({f"policy.{k}": v for k, v in pol["facts"].items()})

    prot = protected_identity.evaluate(workspace, mutations_applied=mutations_applied or [])
    plugin_results["protected_identity"] = prot
    facts.update({f"protected.{k}": v for k, v in prot["facts"].items()})

    if target_verdict is not None:
        re = report_exit.evaluate(workspace, target_verdict)
        plugin_results["report_exit"] = re
        facts.update({f"channels.{k}": v for k, v in re["facts"].items()})

    # Determine validity based on oracle type / expected conditions.
    # valid=True means "world state satisfies required invariants" (benign/control).
    # valid=False means "required invariants are violated" (attack should be rejected).
    if otype == "required_execution_set":
        all_required = bool(expected.get("all_required_tests_executed", True))
        discovered = int(disc["facts"].get("discovered_count", 0))
        required_min = int(expected.get("minimum_required", 1))
        executed_ok = discovered >= required_min and disc["facts"].get("discovery_nonempty", False)
        # If expected says all_required_tests_executed=false, oracle validity is false
        # when tests were not executed / not discovered.
        if all_required is False:
            valid = False
            reasons.append("required_tests_not_executed")
        else:
            valid = executed_ok
            if not valid:
                reasons.append("required_tests_missing_or_not_executed")
        evidence.append("oracle/discovery.json")

    elif otype == "revision_binding":
        bound = bool(rev["facts"].get("evidence_matches_revision", False))
        if expected.get("evidence_revision_matches") is False:
            valid = False
            reasons.append("evidence_revision_does_not_match_target")
        else:
            valid = bound
            if not valid:
                reasons.append("evidence_revision_does_not_match_target")
        evidence.append("oracle/revision-binding.json")

    elif otype == "report_exit_consistency":
        consistent = bool(plugin_results.get("report_exit", {}).get("facts", {}).get("consistent", True))
        if expected.get("channels_consistent") is False:
            valid = False
            reasons.append("exit_code_and_report_disagree")
        else:
            valid = consistent
            if not valid:
                reasons.append("exit_code_and_report_disagree")
        evidence.append("oracle/report-exit.json")

    elif otype == "required_policy_presence":
        present = bool(pol["facts"].get("policy_present", False))
        if expected.get("policy_present") is False:
            valid = False
            reasons.append("required_policy_missing")
        else:
            valid = present
            if not valid:
                reasons.append("required_policy_missing")
        evidence.append("oracle/policy-presence.json")

    elif otype == "protected_identity":
        intact = bool(prot["facts"].get("protected_path_intact", True))
        if expected.get("protected_path_intact") is False:
            valid = False
            reasons.append("protected_semantic_identity_lost")
        else:
            valid = intact
            if not valid:
                reasons.append("protected_semantic_identity_lost")
        evidence.append("oracle/protected-identity.json")

    elif otype == "composite":
        # Combine plugin expectations.
        valids = []
        for p in plugins_cfg:
            sub = evaluate_oracle(
                workspace,
                attack_oracle=p,
                baseline=baseline,
                target_verdict=target_verdict,
                mutations_applied=mutations_applied,
            )
            plugin_results[p.get("type", "sub")] = sub.to_dict()
            valids.append(sub.valid)
            reasons.extend(sub.reasons)
            evidence.extend(sub.evidence)
        if any(v is None for v in valids):
            valid = None
        else:
            valid = all(bool(v) for v in valids)
    else:
        # Fail closed: unknown oracle type is inconclusive, not accepting.
        return OracleResult(
            valid=None,
            reasons=[f"unknown_oracle_type:{otype}"],
            evidence=evidence,
            facts=facts,
            disagreement=False,
            plugins=plugin_results,
        )

    # Never allow target_verdict.accepted to flip oracle validity.
    return OracleResult(
        valid=valid,
        reasons=reasons,
        evidence=evidence,
        facts=facts,
        disagreement=False,
        plugins=plugin_results,
    )
