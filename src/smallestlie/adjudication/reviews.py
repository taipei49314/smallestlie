"""Case-specific post-run research review, independently authenticated."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from smallestlie.attacks.adjudication import choice, mapping, sha256, string, strings
from smallestlie.attacks.schema import AttackSchemaError, load_mapping_bytes
from smallestlie.campaign.preregistration import (
    PreparedRun, PreregistrationError, canonical_digest, case_binding, commit,
    digest, integer, json_mapping,
)


@dataclass(frozen=True)
class TrustedReviewEnvelope:
    provider_id: str
    immutable_ref: str
    binding_sha256: str
    review_sha256: str


class ReviewAuthority(Protocol):
    def verify(self, prepared: PreparedRun, case_id: str,
               review_sha256: str) -> TrustedReviewEnvelope | None:
        """Authenticate an independent post-run review, not YAML hypotheses.

        The authority attests the reviewer's complete pinned-source assessment
        and case-specific semantic coverage/near-shape judgment. A hash, a
        self-reported reviewer name or a case manifest cannot grant this trust.
        """
        ...


@dataclass(frozen=True)
class CaseReview:
    case_id: str
    review_sha256: str | None
    provenance_ref: str | None
    theater: str | None
    scope: str | None
    residual: str | None
    row_refs: tuple[str, ...]
    twin_relation: str | None
    twin_fingerprints: tuple[str, ...]
    reasons: tuple[str, ...]


def frozen_spec(prepared: PreparedRun, case_id: str) -> dict:
    manifest = json_mapping(prepared.manifest_bytes, "prepared manifest")
    declaration = next(case for case in manifest["cases"] if case["case_id"] == case_id)
    data = prepared.asset(declaration["spec_path"])
    if digest(data) != prepared.binding(case_id)["spec_sha256"]:
        raise PreregistrationError("frozen_spec_binding_mismatch")
    return load_mapping_bytes(data, source_path=declaration["spec_path"])


def validate_case_review(
    prepared: PreparedRun, case_id: str, review_bytes: bytes | None,
    observations: dict[str, dict[str, str]], *, authority: ReviewAuthority | None,
) -> CaseReview:
    review_sha = digest(review_bytes) if type(review_bytes) is bytes else None
    try:
        if review_sha is None:
            raise PreregistrationError("post_run_review_missing")
        raw = json_mapping(review_bytes, "case review")
        mapping(raw, "case review", {"schema_version", "binding", "engine", "residual_index_sha256",
                "observations", "source_reviews", "citations", "theater", "scope", "residual", "twin"})
        lock = prepared.lock()
        formal_binding = case_binding(lock, case_id)
        if (raw["schema_version"] != "smallestlie.case-review/v1"
                or raw["binding"] != formal_binding or raw["engine"] != lock["engine"]
                or raw["residual_index_sha256"] != lock["residual_index_sha256"]
                or raw["observations"] != observations):
            raise PreregistrationError("post_review_identity_or_observation_mismatch")
        if authority is None:
            raise PreregistrationError("post_review_provenance_missing")
        envelope = authority.verify(prepared, case_id, review_sha)
        if (not isinstance(envelope, TrustedReviewEnvelope)
                or envelope.binding_sha256 != canonical_digest(formal_binding)
                or envelope.review_sha256 != review_sha):
            raise PreregistrationError("independent_review_envelope_mismatch")
        string(envelope.provider_id, "review provider")
        commit(envelope.immutable_ref, "immutable case review")
        manifest = json_mapping(prepared.manifest_bytes, "manifest")
        index_bytes = prepared.asset(manifest["residual_index_path"])
        if digest(index_bytes) != lock["residual_index_sha256"]:
            raise PreregistrationError("review_index_binding_mismatch")
        index = json_mapping(index_bytes, "reviewed index")
        sources = {item["id"]: item for item in index["sources"]}
        if not isinstance(raw["source_reviews"], list):
            raise PreregistrationError("source_reviews_must_enumerate_complete_documents")
        seen = set()
        for item in raw["source_reviews"]:
            mapping(item, "source review", {"source_id", "sha256", "rationale"})
            sid = string(item["source_id"], "reviewed source")
            if sid in seen or sid not in sources:
                raise PreregistrationError("unknown_or_duplicate_reviewed_source")
            seen.add(sid)
            source = sources[sid]
            if item["sha256"] != source["sha256"] or digest(prepared.asset(source["path"])) != source["sha256"]:
                raise PreregistrationError("review_source_digest_mismatch")
            string(item["rationale"], "complete-source review rationale")
        if seen != sources.keys():
            raise PreregistrationError("partial_index_absence_is_not_complete_source_review")
        if not isinstance(raw["citations"], list):
            raise PreregistrationError("review_citations_must_be_list")
        for citation in raw["citations"]:
            mapping(citation, "citation", {"source_id", "start_line", "end_line", "quote_sha256"})
            sid = string(citation["source_id"], "citation source")
            if sid not in sources:
                raise PreregistrationError("citation_source_not_frozen")
            lines = prepared.asset(sources[sid]["path"]).splitlines(keepends=True)
            first = integer(citation["start_line"], "citation start", minimum=1)
            last = integer(citation["end_line"], "citation end", minimum=first)
            sha256(citation["quote_sha256"], "citation quote")
            if last > len(lines) or digest(b"".join(lines[first - 1:last])) != citation["quote_sha256"]:
                raise PreregistrationError("citation_span_or_quote_mismatch")
        scope = mapping(raw["scope"], "review scope", {"status", "rationale"})
        choice(scope["status"], "review scope", {"in_scope", "out_of_scope", "unresolved"})
        string(scope["rationale"], "scope rationale")
        if scope["status"] != "unresolved" and not raw["citations"]:
            raise PreregistrationError("resolved_scope_requires_source_citation")
        residual = mapping(raw["residual"], "review residual", {"status", "row_refs", "row_reviews", "rationale"})
        status = choice(residual["status"], "review residual", {
            "matched_residual", "no_match_reviewed", "reopened_closed", "unresolved"})
        refs = strings(residual["row_refs"], "review row refs", allow_empty=True)
        string(residual["rationale"], "residual coverage rationale")
        entries = {item["id"]: item for item in index["entries"]}
        expected_status = {"matched_residual": "documented_residual", "reopened_closed": "closed"}.get(status)
        if ((expected_status and not refs) or (status == "no_match_reviewed" and refs)
                or any(ref not in entries or (expected_status and entries[ref]["status"] != expected_status)
                       for ref in refs)):
            raise PreregistrationError("residual_row_status_or_coverage_mismatch")
        if not isinstance(residual["row_reviews"], list):
            raise PreregistrationError("residual_row_reviews_must_be_list")
        reviewed_rows = []
        for row in residual["row_reviews"]:
            mapping(row, "row coverage", {"row_id", "rationale"})
            reviewed_rows.append(string(row["row_id"], "row review id"))
            string(row["rationale"], "case-specific row coverage")
        if len(set(reviewed_rows)) != len(reviewed_rows) or set(reviewed_rows) != set(refs):
            raise PreregistrationError("each_residual_row_requires_case_coverage_review")
        theater = mapping(raw["theater"], "review theater", {"status", "rationale", "changed_paths"})
        choice(theater["status"], "review theater", {"confirmed", "refuted", "unresolved"})
        string(theater["rationale"], "theater rationale")
        changed = strings(theater["changed_paths"], "review changed paths", allow_empty=True)
        case = prepared.binding(case_id)
        before, after = case["arms"]["baseline"]["files"], case["arms"]["attack"]["files"]
        actual_changes = {path for path in before.keys() | after.keys() if before.get(path) != after.get(path)}
        if set(changed) != actual_changes:
            raise PreregistrationError("review_diff_does_not_match_frozen_variants")
        spec = frozen_spec(prepared, case_id)
        oracle = spec["oracle"]
        if theater["status"] == "confirmed":
            expected = oracle.get("expected")
            if not isinstance(expected, dict):
                raise PreregistrationError("unsupported_theater_declaration")
            expected_paths = strings(expected.get("paths"), "declared theater paths", allow_empty=True)
            if (oracle.get("type") != "git_diff_theater" or expected.get("no_theater") is not False
                    or not actual_changes.intersection(expected_paths)):
                raise PreregistrationError("reviewed_theater_not_materialized_as_declared")
        twin = spec["adjudication"]["twin"]
        relation, fingerprints = None, []
        if twin is None:
            if raw["twin"] is not None:
                raise PreregistrationError("undeclared_review_twin")
        else:
            review_twin = mapping(raw["twin"], "review twin", {"status", "rationale", "contrast_sha256", "finding_fingerprints"})
            relation = choice(review_twin["status"], "review twin relation", {"confirmed", "refuted", "unresolved"})
            string(review_twin["rationale"], "near-shape semantic rationale")
            if review_twin["contrast_sha256"] != digest(twin["contrast"].encode("utf-8")):
                raise PreregistrationError("review_twin_contrast_mismatch")
            fingerprints = strings(review_twin["finding_fingerprints"], "review twin fingerprints", allow_empty=True)
        return CaseReview(case_id, review_sha, envelope.immutable_ref, theater["status"], scope["status"],
                          status, tuple(refs), relation, tuple(fingerprints), ())
    except (ValueError, TypeError, KeyError, OSError, StopIteration, AttackSchemaError) as exc:
        return CaseReview(case_id, review_sha, None, None, None, None, (), None, (), (str(exc),))
