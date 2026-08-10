"""Declared behavior claims — trust only after named meters pass."""

from __future__ import annotations

from typing import Any

# claim_id -> {statement, meters[], min_verdicts}
BEHAVIOR_CLAIMS: list[dict[str, Any]] = [
    {
        "claim_id": "containment.path_and_source",
        "statement": "Path escape and in-place source mutation are blocked.",
        "required_meters": ["containment.policy_surface", "inventory.test_surface"],
    },
    {
        "claim_id": "containment.env_and_commands",
        "statement": "Credential env scrubbed; unapproved commands blocked; network denied default.",
        "required_meters": ["containment.policy_surface"],
    },
    {
        "claim_id": "oracle.never_target_verdict",
        "statement": "Oracle validity is not defined by target accepted flag alone.",
        "required_meters": ["oracle.independence_static"],
    },
    {
        "claim_id": "catalog.m1_family_breadth",
        "statement": "Canonical M1 catalog exercises declared core attack families.",
        "required_meters": ["catalog.family_coverage"],
    },
    {
        "claim_id": "fixture.matrix_ready",
        "statement": "naive_gate, honest_gate, and composition_blind_gate fixtures exist and are loadable.",
        "required_meters": ["fixture.matrix"],
    },
    {
        "claim_id": "fixture.behavior_via_ci_summary",
        "statement": "When a ci-summary exists, naive FA + honest clean expectations were met.",
        "required_meters": ["campaign.ci_profiles_if_present"],
        "optional_if_not_measured": True,
    },
    {
        "claim_id": "composition.compound_only",
        "statement": "Compound corpus and composition fixture exist (compound-only behavior covered by tests/meters).",
        "required_meters": ["fixture.matrix", "catalog.composition_presence"],
    },
    {
        "claim_id": "ci.skipped_not_pass",
        "statement": "CI projection never treats SKIPPED/BLOCKED as success.",
        "required_meters": ["ci.status_projection"],
    },
    {
        "claim_id": "ledger.tamper_detectable",
        "statement": "Ledger tampering is detectable by verify.",
        "required_meters": ["inventory.test_surface"],
    },
    {
        "claim_id": "determinism.plan_seed",
        "statement": "Identical seed and baseline produce identical plan digests.",
        "required_meters": ["inventory.test_surface"],
    },
    {
        "claim_id": "incompleteness.visible",
        "statement": "INCONCLUSIVE/INAPPLICABLE/BLOCKED/HARNESS_ERROR are tracked, not hidden.",
        "required_meters": ["catalog.incompleteness_hooks", "ci.status_projection"],
    },
]


def evaluate_claim_trust(
    measurements: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    For each claim, allow trust only if every required meter is MEASURED_PASS.

    If optional_if_not_measured and all required meters are NOT_MEASURED, claim is
    deferred (trust_allowed=False but severity soft — not a suite hard-fail alone).
    """
    out: list[dict[str, Any]] = []
    for claim in BEHAVIOR_CLAIMS:
        meters = list(claim["required_meters"])
        optional = bool(claim.get("optional_if_not_measured"))
        missing = [m for m in meters if m not in measurements]
        not_measured = [
            m
            for m in meters
            if m in measurements and measurements[m].get("verdict") == "NOT_MEASURED"
        ]
        failed = [
            m
            for m in meters
            if m in measurements
            and measurements[m].get("verdict")
            not in {"MEASURED_PASS", "NOT_MEASURED"}
        ]
        hard_failed = [
            m
            for m in meters
            if m in measurements and measurements[m].get("verdict") == "MEASURED_FAIL"
        ]

        deferred = False
        if missing:
            trust = False
            reason = f"meters not run: {missing}"
        elif hard_failed:
            trust = False
            reason = f"meters FAILED: {hard_failed}"
        elif not_measured and optional and not failed:
            trust = False
            deferred = True
            reason = f"deferred until meters run: {not_measured}"
        elif not_measured and not optional:
            trust = False
            reason = f"meters NOT_MEASURED: {not_measured}"
        elif failed:
            trust = False
            reason = f"meters not PASS: {failed}"
        else:
            trust = True
            reason = "all required meters MEASURED_PASS"

        out.append(
            {
                "claim_id": claim["claim_id"],
                "statement": claim["statement"],
                "required_meters": meters,
                "trust_allowed": trust,
                "deferred": deferred,
                "reason": reason,
            }
        )
    return out
