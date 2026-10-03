"""Pure, complete-denominator research adjudication; v1 scores stay separate."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Mapping

from smallestlie.adjudication.observations import (
    VerifierAuthority, VerifierObservation, validate_verifier_observation,
)
from smallestlie.adjudication.reviews import (
    CaseReview, ReviewAuthority, frozen_spec, validate_case_review,
)
from smallestlie.campaign.preregistration import PreparedRun, canonical_digest
from smallestlie.oracle.runner_evidence import (
    EffectivenessAssessment, ExecutionAuthority, RunnerEvidenceValidation,
    assess_effectiveness, validate_runner_receipt,
)


class AdjudicationError(ValueError):
    pass


@dataclass(frozen=True)
class CaseInputs:
    runner_receipt: bytes | None = None
    runner_artifacts: dict[str, bytes] = field(default_factory=dict)
    verifier_metadata: bytes | None = None
    verifier_stdout: bytes | None = None
    verifier_stderr: bytes | None = None
    review: bytes | None = None


@dataclass(frozen=True)
class AdjudicatedCase:
    case_id: str
    preregistered_class: str
    verdict: str
    paired_headline: bool
    twin_case_id: str | None
    reasons: tuple[str, ...]
    effectiveness: EffectivenessAssessment
    runner: RunnerEvidenceValidation
    verifier: VerifierObservation
    review: CaseReview

    def to_dict(self) -> dict:
        result = asdict(self)
        result["verifier"]["findings"] = [finding.to_dict() for finding in self.verifier.findings]
        return result


@dataclass(frozen=True)
class AdjudicationReport:
    lock_digest: str
    cases: tuple[AdjudicatedCase, ...]

    def to_dict(self) -> dict:
        counts = Counter(case.verdict for case in self.cases)
        return {"schema_version": "smallestlie.adjudication/v1", "lock_digest": self.lock_digest,
                "frozen_case_count": len(self.cases), "verdict_counts": dict(sorted(counts.items())),
                "confirmed_defect_case_count": counts["confirmed_defect"],
                "paired_defect_case_count": sum(case.paired_headline for case in self.cases),
                "cases": [case.to_dict() for case in self.cases]}


def _qualified_twin(prepared: PreparedRun, case_id: str, review: CaseReview,
                    assessments: dict[str, EffectivenessAssessment],
                    observations: dict[str, VerifierObservation]) -> tuple[bool, tuple[str, ...]]:
    twin_id, reasons = twin_binding_effectiveness(prepared, case_id, assessments)
    if twin_id is None:
        return False, reasons
    observed = observations[twin_id]
    if observed.accepted is not False or observed.reasons or observed.provenance_ref is None:
        return False, ("control_own_valid_verifier_block_required",)
    return twin_finding_relation(prepared, case_id, review, observed)


def twin_binding_effectiveness(prepared: PreparedRun, case_id: str, assessments: dict) -> tuple:
    """Pure frozen near-shape identity and own effectiveness predicates."""
    parent = prepared.binding(case_id)
    twin_id = parent["twin_case_id"]
    if twin_id is None:
        return None, ("no_preregistered_detectable_twin",)
    twin = prepared.binding(twin_id)
    if (twin["preregistered_class"] != "CTL" or twin["control_role"] != "detectable_attack_control"
            or twin["twin_case_id"] is not None
            or parent["arms"]["twin"] != twin["arms"]["attack"]
            or any(parent["arms"][role] != twin["arms"][role] for role in ("baseline", "repair"))):
        return None, ("twin_frozen_variant_or_role_mismatch",)
    if (assessments[case_id].twin != "confirmed" or assessments[twin_id].attack != "confirmed"):
        return None, ("parent_twin_and_control_own_effectiveness_required",)
    # Do not borrow a control's result solely because its fixture tree matches.
    if prepared.profile(case_id)["arms"]["twin"] != prepared.profile(twin_id)["arms"]["attack"]:
        return None, ("twin_and_control_command_context_differ",)
    return twin_id, ()


def twin_finding_relation(prepared: PreparedRun, case_id: str, review, observed) -> tuple:
    """Pure relevant-finding predicate; caller must authenticate observations."""
    if review.twin_relation != "confirmed":
        return False, ("near_shape_semantic_relation_unconfirmed",)
    declaration = frozen_spec(prepared, case_id)["adjudication"]["twin"]
    detection = declaration["detection"]
    relevant = [finding for finding in observed.findings
                if finding.rule in detection["rule_ids"] and finding.path in detection["paths"]
                and finding.fingerprint in review.twin_fingerprints and finding.blocks(observed.fail_on)]
    if not relevant:
        return False, ("no_reviewed_relevant_nonallowlisted_blocking_finding",)
    return True, ("effective_near_shape_control_blocked_by_relevant_finding",)


def adjudicate_campaign(
    prepared: PreparedRun, inputs: Mapping[str, CaseInputs], *,
    runner_authority: ExecutionAuthority | None = None,
    verifier_authority: VerifierAuthority | None = None,
    review_authority: ReviewAuthority | None = None,
) -> AdjudicationReport:
    """Revalidate raw observations, then adjudicate every frozen case once.

    No caller-supplied assessment/accepted flag can create a verdict. Configured
    authorities are independently trusted integration boundaries. Missing
    authorities or captures remain visible. Providers perform retrieval; this
    adjudicator performs no filesystem, subprocess or network operations.
    """
    lock = prepared.lock()
    ids = [case["case_id"] for case in lock["cases"]]
    if len(ids) != len(set(ids)) or set(inputs) - set(ids):
        raise AdjudicationError("duplicate_frozen_or_undeclared_input_case")
    if any(not isinstance(value, CaseInputs) for value in inputs.values()):
        raise AdjudicationError("case_inputs_must_be_raw_capture_objects")
    runner, verifier, assessments = {}, {}, {}
    for cid in ids:
        raw = inputs.get(cid, CaseInputs())
        # The external parser expects bytes and an artifact mapping. Invalid
        # caller types must not turn a missing capture into a real refutation.
        receipt = raw.runner_receipt if type(raw.runner_receipt) is bytes else None
        artifacts = dict(raw.runner_artifacts) if isinstance(raw.runner_artifacts, dict) else {}
        runner[cid] = validate_runner_receipt(prepared, cid, receipt, artifacts, authority=runner_authority)
        assessments[cid] = assess_effectiveness(prepared, runner[cid])
        verifier[cid] = validate_verifier_observation(prepared, cid, raw.verifier_metadata,
            raw.verifier_stdout, raw.verifier_stderr, authority=verifier_authority)
    rows = []
    for cid in ids:
        case = prepared.binding(cid)
        twin_id = case["twin_case_id"]
        linked = [cid] + ([twin_id] if twin_id else [])
        observation_refs = {key: {"runner_validation_sha256": canonical_digest(asdict(runner[key])),
                                 "verifier_validation_sha256": verifier[key].validation_sha256}
                            for key in linked}
        review = validate_case_review(prepared, cid, inputs.get(cid, CaseInputs()).review,
                                      observation_refs, authority=review_authority)
        effect, observed = assessments[cid], verifier[cid]
        paired = False
        verdict, reasons = case_verdict(case, effect, observed, review,
                                        review_trusted=review.provenance_ref is not None)
        if verdict == "confirmed_defect":
            paired, twin_reasons = _qualified_twin(prepared, cid, review, assessments, verifier)
            reasons.extend(twin_reasons)
        rows.append(AdjudicatedCase(cid, case["preregistered_class"], verdict, paired, twin_id,
            tuple(reasons), effect, runner[cid], observed, review))
    return AdjudicationReport(lock["lock_digest"], tuple(rows))


def case_verdict(case: dict, effect, observed, review, *, review_trusted: bool) -> tuple:
    """Pure decision order, after each caller's version-specific authority gates."""
    reasons = []
    if case["preregistered_class"] == "CTL":
        verdict = ("control_rejected" if observed.accepted is False else
                   "control_accepted" if observed.accepted is True else "unknown")
        reasons.append("controls_are_retained_without_defect_credit")
    elif effect.attack == "refuted":
        verdict = "killed_candidate" if case["preregistered_class"] == "DEF" else "ineffective_candidate"
        reasons.extend(effect.attack_reasons)
    elif observed.accepted is False:
        verdict = "attack_rejected"
        reasons.append("valid_verifier_block_effectiveness_recorded_separately")
    elif effect.attack != "confirmed" or observed.accepted is None:
        verdict = "unknown"
        reasons.extend((*effect.attack_reasons, *observed.reasons))
    elif not review_trusted or review.reasons:
        verdict = "unknown"
        reasons.extend(review.reasons)
    elif review.theater != "confirmed" or review.scope != "in_scope" or review.residual == "unresolved":
        verdict = "boundary"
        reasons.append("theater_scope_or_residual_coverage_not_eligible")
    elif review.residual == "matched_residual":
        verdict = "documented_residual"
        reasons.append("effective_bypass_matches_reviewed_documented_residual")
    else:
        verdict = "confirmed_defect"
        reasons.append("reviewed_reopened_closed_row" if review.residual == "reopened_closed"
                       else "effective_in_scope_bypass_after_complete_source_review")
    return verdict, reasons
