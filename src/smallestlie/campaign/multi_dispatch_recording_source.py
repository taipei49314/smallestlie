"""Accepted immutable J bytes, followed by the existing full fresh re-verification.

The integration supplies a separate exact publication registry for J. J never
supplies runner, collector, human or semantic approval. No supervisor, launcher,
local recording, authority discovery or legacy gate is used.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace

from smallestlie.attacks.adjudication import DeclarationError, sha256
from smallestlie.campaign.evidence_sources import EcReceiptStore, _artifact_path
from smallestlie.campaign.lifecycle import ArtifactStore
from smallestlie.campaign.multi_dispatch_observations import _configuration, _stable_authority
from smallestlie.campaign.multi_dispatch_recording import MultiDispatchRecording, _verify_raw_recording
from smallestlie.campaign.multi_dispatch_review_source import (
    GitHubMultiDispatchReviewAuthority, _fresh_governance_store,
)
from smallestlie.campaign.multi_dispatch_sources import EcMultiDispatchSourceMapAuthority, _fresh_store
from smallestlie.campaign.preregistration import PreparedRun, canonical_digest
from smallestlie.campaign.provenance import GovernanceReference, ProvenanceError
from smallestlie.ledger.lifecycle import artifact_ref


@dataclass(frozen=True)
class MultiDispatchRecordingLocation:
    journal_path: str
    journal_sha256: str
    artifacts_prefix: str

    def __post_init__(self):
        try:
            _artifact_path(self.journal_path)
            _artifact_path(self.artifacts_prefix)
            sha256(self.journal_sha256, "externally accepted raw J digest")
        except DeclarationError as exc:
            raise ProvenanceError("invalid independently configured immutable J location") from exc
        prefix = self.artifacts_prefix.casefold()
        if (self.journal_path.casefold() in {"ec-publication.json", "ec-workload.json", prefix}
                or self.journal_path.casefold().startswith(prefix + "/")
                or prefix in {"ec-publication.json", "ec-workload.json"}):
            raise ProvenanceError("J, artifact prefix and EC metadata require separate paths")


class EcMultiDispatchRecordingAuthority:
    def __init__(self, store: EcReceiptStore, location: MultiDispatchRecordingLocation):
        _fresh_store(store)
        if type(location) is not MultiDispatchRecordingLocation:
            raise ProvenanceError("exact independently configured J location required")
        self.store, self.location = store, location


@dataclass(frozen=True)
class PublishedMultiDispatchRecording:
    repository: str
    repository_id: int
    receipt_commit: str
    run_id: int
    attempt: int
    job_id: int
    publication_sha256: str
    acceptance_ref: str
    location: MultiDispatchRecordingLocation
    recording: MultiDispatchRecording


@dataclass(frozen=True)
class _VerifiedJMaterial:
    """Private bytes from one completed acquisition; never an authority input."""
    published: PublishedMultiDispatchRecording
    journal: bytes
    artifacts: tuple[tuple[str, bytes], ...]


def _j_configuration(authority):
    if type(authority) is not EcMultiDispatchRecordingAuthority:
        raise ProvenanceError("exact external immutable J authority required")
    EcMultiDispatchRecordingAuthority(authority.store, authority.location)
    return canonical_digest({"root": asdict(authority.store.root), "location": asdict(authority.location)})


def _review_configuration(authority):
    if authority is None:
        return None
    if type(authority) is not GitHubMultiDispatchReviewAuthority:
        raise ProvenanceError("exact independent semantic review authority required")
    _fresh_governance_store(authority.store)
    GitHubMultiDispatchReviewAuthority(authority.store, grants=authority.grants)
    root = asdict(authority.store.root)
    for role in ("product", "requests", "reviews"):
        root[role]["merger_ids"] = sorted(root[role]["merger_ids"])
    return canonical_digest({"root": root,
        "grants": [asdict(item) for item in authority.grants]})


def _check_roles(prepared, store, sources, reviews, report=None):
    """Known configuration contradicts J before any unavailable GET can mask it."""
    root, publication = store.root, store.root.publications[0]
    archive, grant = sources.archive.root, sources.grant
    if root.product_repository.casefold() != archive.product_repository.casefold():
        raise ProvenanceError("J and observation product trust roots differ")
    repositories = [(archive.product_repository, None)]
    try:
        repositories.append((GovernanceReference.parse(prepared.request.authorization_ref).repository, None))
    except ValueError:
        pass
    revisions = {prepared.request.source_commit, prepared.lock()["phase1_commit"], publication.ec_source_commit,
        grant.anchor.commit, grant.evidence_commit, archive.publications[0].receipt_commit,
        archive.publications[0].ec_source_commit}
    refs = {prepared.request.authorization_ref, archive.publications[0].acceptance_ref,
        *[getattr(grant, name + "_acceptance_ref") for name in ("anchor", "publisher", "coordinator", "mapping")]}
    if archive.publications[0].supervisor_acceptance_ref is not None:
        refs.add(archive.publications[0].supervisor_acceptance_ref)
    for member in sources.actions:
        if member.authority is None:
            continue
        action = member.authority
        own = action.store.root.publications[0]
        revisions.update((own.receipt_commit, own.ec_source_commit, action.admission.evidence_commit))
        refs.update((own.acceptance_ref, action.admission.collector_acceptance_ref,
            action.admission.host_storage_acceptance_ref, action.admission.journal_acceptance_ref))
        if own.supervisor_acceptance_ref is not None:
            refs.add(own.supervisor_acceptance_ref)
    if reviews is not None:
        governance = reviews.store.root
        repositories.extend((item.full_name, item.repository_id)
                            for item in (governance.product, governance.requests, governance.reviews))
        revisions.update(item.merge_commit for item in governance.human_approvals)
        refs.update(item.reference for item in governance.human_approvals)
        refs.update(item.reference for item in reviews.grants)
        refs.update(item.semantic_approval_ref for item in reviews.grants)
    if report is not None:
        revisions.update(item.commit for item in report.snapshot.source_roles if item.commit is not None)
        refs.update(report.snapshot.acceptance_refs)
        revisions.update(row.review.provenance_ref for row in report.cases if row.review.provenance_ref is not None)
        refs.update(row.review.semantic_approval_ref for row in report.cases if row.review.semantic_approval_ref is not None)
    if any(root.repository.casefold() == name.casefold() or root.repository_id == rid
           for name, rid in repositories):
        raise ProvenanceError("J publication aliases product/request/review repository")
    if publication.receipt_commit in revisions:
        raise ProvenanceError("J output aliases an immutable source/input/claimed output")
    if publication.acceptance_ref in refs:
        raise ProvenanceError("J acceptance aliases source/human/semantic acceptance")


class _PublishedArtifacts:
    def __init__(self, receipt, prefix):
        self.files, self.prefix, self.used = dict(receipt.files), prefix + "/", set()

    def read(self, ref):
        artifact_ref(ref)
        if ref["state"] == "missing":
            return None
        path = self.prefix + ref["sha256"]
        raw = self.files.get(path)
        if raw is None or ArtifactStore.reference(raw) != ref:
            raise ProvenanceError("immutable J artifact missing or raw size/digest mismatch")
        self.used.add(path)
        return raw

    def check_closure(self):
        if {path for path in self.files if path.startswith(self.prefix)} != self.used:
            raise ProvenanceError("immutable J artifact prefix has unreferenced content")


def verify_published_multi_dispatch_recording(prepared: PreparedRun, *,
        recording_authority: EcMultiDispatchRecordingAuthority,
        source_authority: EcMultiDispatchSourceMapAuthority,
        review_authority=None) -> PublishedMultiDispatchRecording:
    """GET exact accepted J; recompute every row with fresh original authorities.

    The transport is the existing explicitly trusted integration boundary.
    Saved carriers, J hashes and publication success grant no semantic facts.
    """
    return _acquire_verified_recording(prepared, recording_authority=recording_authority,
        source_authority=source_authority, review_authority=review_authority).published


def _acquire_verified_recording(prepared: PreparedRun, *,
        recording_authority: EcMultiDispatchRecordingAuthority,
        source_authority: EcMultiDispatchSourceMapAuthority,
        review_authority=None) -> _VerifiedJMaterial:
    """Share one fresh acquisition with export; preserve its exact raw closure."""
    if type(prepared) is not PreparedRun or type(source_authority) is not EcMultiDispatchSourceMapAuthority:
        raise ProvenanceError("exact frozen preparation and original source authority required")
    configured = (_j_configuration(recording_authority), _configuration(source_authority),
                  _review_configuration(review_authority))
    original_transport = recording_authority.store.transport
    source_transports = [source_authority.archive.transport,
        *[item.authority.store.transport for item in source_authority.actions if item.authority is not None]]
    review_transport = None if review_authority is None else review_authority.store.transport

    def require_unchanged():
        current = (_j_configuration(recording_authority), _configuration(source_authority),
                   _review_configuration(review_authority))
        current_sources = [source_authority.archive.transport,
            *[item.authority.store.transport for item in source_authority.actions if item.authority is not None]]
        if (current != configured or recording_authority.store.transport is not original_transport
                or len(current_sources) != len(source_transports)
                or any(a is not b for a, b in zip(current_sources, source_transports))
                or (review_authority is not None and review_authority.store.transport is not review_transport)):
            raise ProvenanceError("imported J/source/review configuration changed during acquisition")

    root = recording_authority.store.root
    store = EcReceiptStore(replace(root, publications=tuple(replace(item) for item in root.publications)),
                           transport=original_transport)
    location = replace(recording_authority.location)
    sources = _stable_authority(source_authority)
    reviews = None if review_authority is None else GitHubMultiDispatchReviewAuthority(
        _fresh_governance_store(review_authority.store),
        grants=tuple(replace(item) for item in review_authority.grants))
    _check_roles(prepared, store, sources, reviews)
    receipt = EcReceiptStore.read(store, prepared)
    require_unchanged()
    artifacts = _PublishedArtifacts(receipt, location.artifacts_prefix)
    data = dict(receipt.files).get(location.journal_path)
    result = _verify_raw_recording(data, prepared, artifacts,
        expected_journal_sha256=location.journal_sha256,
        source_authority=sources, review_authority=reviews)
    artifacts.check_closure()
    _check_roles(prepared, store, sources, reviews, result.report)
    require_unchanged()
    publication = receipt.grant
    published = PublishedMultiDispatchRecording(root.repository, root.repository_id, publication.receipt_commit,
        publication.run_id, publication.attempt, publication.job_id, publication.publication_sha256,
        publication.acceptance_ref, location, result)
    closure = tuple((path.removeprefix(artifacts.prefix), artifacts.files[path])
                    for path in sorted(artifacts.used))
    return _VerifiedJMaterial(published, data, closure)
