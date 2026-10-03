"""Complete-denominator mapped adjudication with source reacquisition at entry."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from typing import Mapping

from smallestlie.adjudication.engine import (
    AdjudicationError, case_verdict, twin_binding_effectiveness, twin_finding_relation,
)
from smallestlie.adjudication.mapped_reviews import MappedCaseReview, validate_mapped_case_review
from smallestlie.campaign.mapped_observations import (
    MappedCaseObservation, MappedObservationSnapshot, read_mapped_observations,
)
from smallestlie.campaign.preregistration import PreparedRun
from smallestlie.campaign.source_map import EcLifecycleSourceMapAuthority

SCHEMA = "smallestlie.mapped-adjudication/v1"


@dataclass(frozen=True)
class MappedAdjudicatedCase:
    case_id: str
    preregistered_class: str
    verdict: str
    paired_headline: bool
    twin_case_id: str | None
    reasons: tuple[str, ...]
    observation: MappedCaseObservation
    review: MappedCaseReview

    def to_dict(self) -> dict:
        result = asdict(self)
        result["observation"]["verifier"]["findings"] = [
            finding.to_dict() for finding in self.observation.verifier.findings]
        return result


@dataclass(frozen=True)
class MappedAdjudicationReport:
    snapshot: MappedObservationSnapshot
    cases: tuple[MappedAdjudicatedCase, ...]

    def to_dict(self) -> dict:
        counts = Counter(case.verdict for case in self.cases)
        return {"schema_version": SCHEMA, "lock_digest": self.snapshot.lock_digest,
                "snapshot_sha256": self.snapshot.validation_sha256,
                "snapshot": asdict(self.snapshot), "frozen_case_count": len(self.cases),
                "verdict_counts": dict(sorted(counts.items())),
                "confirmed_defect_case_count": counts["confirmed_defect"],
                "paired_defect_case_count": sum(case.paired_headline for case in self.cases),
                "cases": [case.to_dict() for case in self.cases]}


def _qualified_mapped_twin(prepared, case_id, review, observations):
    twin_id, reasons = twin_binding_effectiveness(prepared, case_id,
        {cid: item.effectiveness for cid, item in observations.items()})
    if twin_id is None:
        return False, reasons
    observed = observations[twin_id].verifier
    actions = (observed.command, *observed.materializations)
    if (observed.accepted is not False or observed.reasons
            or any(item.eligible is not True or item.state != "observed"
                   or item.action_receipt_ref is None or item.termination_kind != "completed" for item in actions)):
        return False, ("control_own_valid_mapped_verifier_block_required",)
    return twin_finding_relation(prepared, case_id, review, observed)


def adjudicate_mapped_campaign(prepared: PreparedRun, reviews: Mapping[str, bytes | None], *,
                               source_authority: EcLifecycleSourceMapAuthority,
                               review_authority=None) -> MappedAdjudicationReport:
    """Accept raw reviews and configured readers, never a constructed snapshot.

    Reacquire the whole source map, archive and action receipts before making
    any decision. A structural rejection aborts rather than lending stale PASS;
    incomplete semantic observations stay in the complete frozen denominator.
    """
    if not isinstance(reviews, Mapping):
        raise AdjudicationError("mapped_reviews_require_raw_bytes_or_missing")
    reviews = dict(reviews)
    if any(type(value) is not bytes and value is not None for value in reviews.values()):
        raise AdjudicationError("mapped_reviews_require_raw_bytes_or_missing")
    snapshot = read_mapped_observations(prepared, authority=source_authority)
    if snapshot is None:
        raise AdjudicationError("mapped_source_reacquisition_rejected")
    ids = [case["case_id"] for case in prepared.lock()["cases"]]
    if len(ids) != len(set(ids)) or set(reviews) - set(ids) or [item.case_id for item in snapshot.cases] != ids:
        raise AdjudicationError("mapped_duplicate_missing_or_undeclared_case")
    observations = {item.case_id: item for item in snapshot.cases}
    rows = []
    for cid in ids:
        binding, observed = prepared.binding(cid), observations[cid]
        review = validate_mapped_case_review(prepared, cid, reviews.get(cid), snapshot, authority=review_authority)
        verdict, reasons = case_verdict(binding, observed.effectiveness, observed.verifier, review,
            review_trusted=review.provenance_ref is not None and review.semantic_approval_ref is not None)
        paired = False
        if verdict == "confirmed_defect":
            paired, twin_reasons = _qualified_mapped_twin(prepared, cid, review, observations)
            reasons.extend(twin_reasons)
        rows.append(MappedAdjudicatedCase(cid, binding["preregistered_class"], verdict, paired,
            binding["twin_case_id"], tuple(reasons), observed, review))
    return MappedAdjudicationReport(snapshot, tuple(rows))
