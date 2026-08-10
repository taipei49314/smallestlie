"""Independent ground-truth oracle orchestration (never uses target verdict as truth)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from smallestlie.models import OracleResult, TargetVerdict
from smallestlie.oracle import (
    artifact_hash,
    authority,
    discovery,
    execution_trace,
    path_canonical,
    policy_presence,
    protected_identity,
    report_exit,
    revision_binding,
    semantic_policy,
    verifier_rules,
    workflow,
)


def evaluate_oracle(
    workspace: Path,
    *,
    attack_oracle: dict[str, Any],
    baseline: dict[str, Any],
    target_verdict: TargetVerdict | None = None,
    mutations_applied: list[dict[str, Any]] | None = None,
    cross_check_plugins: list[str] | None = None,
) -> OracleResult:
    """
    Evaluate independent oracles using workspace facts only.

    Validity is derived from observed facts (fact-based), not from the target's
    accepting verdict. Optional expected flags document the attack hypothesis.
    """
    otype = str(attack_oracle.get("type", "composite"))
    expected = dict(attack_oracle.get("expected") or {})
    plugins_cfg = list(attack_oracle.get("plugins") or [])
    mutations_applied = mutations_applied or []

    plugin_results: dict[str, Any] = {}
    reasons: list[str] = []
    evidence: list[str] = []
    facts: dict[str, Any] = {}

    # Collect O2/O3 structural facts from multiple independent plugins.
    disc = discovery.evaluate(workspace)
    plugin_results["discovery"] = disc
    facts.update({f"discovery.{k}": v for k, v in disc["facts"].items()})

    rev = revision_binding.evaluate(workspace, baseline=baseline)
    plugin_results["revision_binding"] = rev
    facts.update({f"revision.{k}": v for k, v in rev["facts"].items()})

    pol = policy_presence.evaluate(workspace)
    plugin_results["policy_presence"] = pol
    facts.update({f"policy.{k}": v for k, v in pol["facts"].items()})

    prot = protected_identity.evaluate(workspace, mutations_applied=mutations_applied)
    plugin_results["protected_identity"] = prot
    facts.update({f"protected.{k}": v for k, v in prot["facts"].items()})

    art = artifact_hash.evaluate(workspace)
    plugin_results["artifact_hash"] = art
    facts.update({f"artifact.{k}": v for k, v in art["facts"].items()})

    ex = execution_trace.evaluate(workspace)
    plugin_results["execution_trace"] = ex
    facts.update({f"execution.{k}": v for k, v in ex["facts"].items()})

    wf = workflow.evaluate(workspace)
    plugin_results["workflow"] = wf
    facts.update({f"workflow.{k}": v for k, v in wf["facts"].items()})

    auth = authority.evaluate(workspace)
    plugin_results["authority"] = auth
    facts.update({f"authority.{k}": v for k, v in auth["facts"].items()})

    sem = semantic_policy.evaluate_semantics(workspace)
    plugin_results["semantic_policy"] = sem
    facts.update({f"semantic.{k}": v for k, v in sem["facts"].items()})

    defaults = semantic_policy.evaluate_defaults(workspace)
    plugin_results["fail_closed_defaults"] = defaults
    facts.update({f"defaults.{k}": v for k, v in defaults["facts"].items()})

    pathc = path_canonical.evaluate(workspace, mutations_applied=mutations_applied)
    plugin_results["path_canonical"] = pathc
    facts.update({f"path.{k}": v for k, v in pathc["facts"].items()})

    vrf = verifier_rules.evaluate(workspace)
    plugin_results["verifier_rules"] = vrf
    facts.update({f"verifier.{k}": v for k, v in vrf["facts"].items()})

    if target_verdict is not None:
        re = report_exit.evaluate(workspace, target_verdict)
        plugin_results["report_exit"] = re
        facts.update({f"channels.{k}": v for k, v in re["facts"].items()})

    disagreement = False
    valid: bool | None

    if otype == "required_execution_set":
        skip = bool(ex["facts"].get("skip_assertions"))
        executed = int(ex["facts"].get("executed_actual_count", 0))
        discovered = int(disc["facts"].get("discovered_count", 0))
        required_min = int(expected.get("minimum_required", 1))
        # Prefer execution-trace actuals when present; fall back to discovery.
        if ex["facts"].get("trace_present"):
            valid = (not skip) and executed >= required_min
        else:
            valid = discovered >= required_min and bool(disc["facts"].get("discovery_nonempty"))
        if not valid:
            reasons.append("required_tests_not_executed")
        evidence.append("oracle/execution-trace.json")

    elif otype == "revision_binding":
        valid = bool(rev["facts"].get("evidence_matches_revision", False))
        if not valid:
            reasons.append("evidence_revision_does_not_match_target")
        evidence.append("oracle/revision-binding.json")

    elif otype == "report_exit_consistency":
        re_facts = plugin_results.get("report_exit", {}).get("facts", {})
        valid = bool(re_facts.get("channels_sound", re_facts.get("consistent", True)))
        if re_facts.get("force_channel_disagree"):
            reasons.append("forced_channel_disagreement_marker")
            valid = False
        elif not re_facts.get("consistent", True):
            reasons.append("exit_code_and_report_disagree")
            valid = False
        evidence.append("oracle/report-exit.json")

    elif otype == "required_policy_presence":
        valid = bool(pol["facts"].get("policy_present", False))
        if not valid:
            reasons.append("required_policy_missing")
        evidence.append("oracle/policy-presence.json")

    elif otype == "protected_identity":
        valid = bool(prot["facts"].get("protected_path_intact", True))
        if not valid:
            reasons.append("protected_semantic_identity_lost")
        evidence.append("oracle/protected-identity.json")

    elif otype == "artifact_hash_binding":
        valid = bool(art["facts"].get("artifact_matches_manifest", False))
        if not valid:
            reasons.append("artifact_hash_mismatch")
        evidence.append("oracle/artifact-hash.json")

    elif otype == "matrix_completeness":
        # Partial run_only or incomplete executed set => invalid
        partial = bool(ex["facts"].get("partial_execution_configured"))
        jobs_ok = bool(wf["facts"].get("required_jobs_complete", False))
        full_exec = bool(ex["facts"].get("all_discovered_executed", False))
        valid = (not partial) and jobs_ok and (full_exec or not ex["facts"].get("trace_present"))
        # If only partial execution is the attack, mark invalid on partial alone.
        if partial:
            valid = False
            reasons.append("partial_execution_configured")
        elif not jobs_ok:
            valid = False
            reasons.append("matrix_incomplete")
        evidence.append("oracle/matrix.json")

    elif otype == "workflow_completeness":
        valid = bool(wf["facts"].get("required_jobs_complete", False))
        if not valid:
            reasons.append("required_jobs_incomplete_or_skipped")
        evidence.append("oracle/workflow.json")

    elif otype == "semantic_policy":
        valid = bool(sem["facts"].get("semantics_intact", True))
        if not valid:
            reasons.append("semantic_inversion_detected")
        evidence.append("oracle/semantic-policy.json")

    elif otype == "fail_closed_defaults":
        valid = bool(defaults["facts"].get("defaults_fail_closed", False))
        if not valid:
            reasons.append("open_default_on_missing_field")
        evidence.append("oracle/fail-closed-defaults.json")

    elif otype == "path_canonicalization":
        valid = bool(pathc["facts"].get("canonical_identity_intact", False))
        if not valid:
            reasons.append("canonical_path_identity_lost")
        evidence.append("oracle/path-canonical.json")

    elif otype == "actor_authority":
        # For completion authority: approver must be authorized when approval required
        # Also fail if require_approval field missing (fail-closed).
        field_ok = bool(auth["facts"].get("require_approval_field_present", False))
        approver_ok = bool(auth["facts"].get("approver_authorized", False))
        # When policy missing entirely, still treat as invalid for authority attacks
        # if approver not in default allowlist — already handled.
        valid = field_ok and approver_ok
        if not field_ok:
            reasons.append("require_approval_field_missing")
        if not approver_ok:
            reasons.append("approver_not_authorized")
        evidence.append("oracle/authority.json")

    elif otype == "verifier_rule_presence":
        valid = bool(vrf["facts"].get("required_rules_intact", False))
        if not valid:
            reasons.append("verifier_required_rules_missing_or_disabled")
        evidence.append("oracle/verifier-rules.json")

    elif otype == "composite":
        valids: list[bool | None] = []
        for p in plugins_cfg:
            sub = evaluate_oracle(
                workspace,
                attack_oracle=p,
                baseline=baseline,
                target_verdict=target_verdict,
                mutations_applied=mutations_applied,
            )
            key = str(p.get("type", "sub"))
            plugin_results[key] = sub.to_dict()
            valids.append(sub.valid)
            reasons.extend(sub.reasons)
            evidence.extend(sub.evidence)
        if not valids:
            valid = None
            reasons.append("empty_composite_oracle")
        elif any(v is None for v in valids):
            valid = None
            disagreement = True
            reasons.append("oracle_plugin_unknown")
        else:
            # Disagreement: one plugin true one false among independent cross-checks
            if cross_check_plugins:
                checks = []
                for name in cross_check_plugins:
                    # re-evaluate named types as independent truth bits
                    bit = evaluate_oracle(
                        workspace,
                        attack_oracle={"type": name},
                        baseline=baseline,
                        target_verdict=target_verdict,
                        mutations_applied=mutations_applied,
                    )
                    checks.append(bit.valid)
                if any(c is None for c in checks):
                    valid = None
                    disagreement = True
                elif len(set(checks)) > 1:
                    valid = None
                    disagreement = True
                    reasons.append("oracle_plugin_disagreement")
                else:
                    valid = all(bool(v) for v in valids)
            else:
                valid = all(bool(v) for v in valids)
    else:
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
        disagreement=disagreement,
        plugins=plugin_results,
    )
