"""JSON projection of offline saved claims; this supplies no authority."""

from smallestlie.campaign.preregistration import digest
from smallestlie.report.multi_dispatch_witness import UnverifiedMultiDispatchWitness

SCHEMA = "smallestlie.multi-dispatch-witness-view/v1"


def render_unverified_multi_dispatch_witness(value):
    """Project the inspector's carrier without reads or adjudication.

    Exact type checking is an API boundary, not authentication of Python callers.
    Saved payloads stay under claimed keys; raw reviews remain opaque bytes.
    """
    if type(value) is not UnverifiedMultiDispatchWitness:
        raise TypeError("unverified_multi_dispatch_witness_required")
    return {
        "schema_version": SCHEMA,
        "structural_status": "inspected",
        "verification_status": "unverified",
        "journal_sha256": value.journal_sha256,
        "manifest_sha256": value.manifest_sha256,
        "case_ids": list(value.case_ids),
        "selected_case_id": value.selected_case_id,
        "source_hint": value.source_hint,
        "raw_reviews": [
            {"case_id": cid, "state": "missing" if raw is None else "present",
             "bytes": None if raw is None else len(raw),
             "sha256": None if raw is None else digest(raw)}
            for cid, raw in value.raw_reviews
        ],
        "claimed_snapshot": value.claimed_snapshot,
        "claimed_review_validations": list(value.claimed_review_validations),
        "claimed_rows": list(value.claimed_rows),
        "claimed_report": value.claimed_report,
    }
