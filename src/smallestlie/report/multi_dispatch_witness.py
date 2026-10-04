"""Portable original J bytes; offline inspection supplies no source authority.

Export reacquires and re-verifies through the published reader once. The plain
bundle contains no resolver, executable helper or imported approval registry.
Saved rows/counts/provenance remain claims when inspected without authorities.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import os
from pathlib import Path
import re
import stat

from smallestlie.attacks.adjudication import DeclarationError, mapping, sha256
from smallestlie.campaign.evidence_sources import MAX_FILES, MAX_TOTAL_BYTES, _artifact_path
from smallestlie.campaign.lifecycle import ArtifactStore, MAX_ARTIFACT, _mkdir, _plain_path, _sync_directory, encoded
from smallestlie.campaign.multi_dispatch_recording_source import _acquire_verified_recording
from smallestlie.campaign.preregistration import PreregistrationError, commit, digest, integer, json_mapping
from smallestlie.ledger.lifecycle import artifact_ref
from smallestlie.ledger.multi_dispatch_recording import read_multi_dispatch_journal

SCHEMA = "smallestlie.multi-dispatch-witness/v1"
README = b"""# Multi-dispatch raw witness

Offline inspection is unverified. Journal, rows, verdicts, counts and provenance
are saved claims. Hash/chain/inventory consistency supplies no publication,
human, semantic, runner or execution authority. A selected case is only a view;
the complete frozen roster, controls, reviews and summary remain in this bundle.

Online verification needs independently configured original preparation and
J/source/review authorities. This bundle provides no grants or replay commands.
Windows directory-entry power-loss durability and hostile concurrent filesystem
writers require separate host/storage adoption; file synchronization alone does
not establish them. An interrupted export is preserved and cannot be resumed.
"""


@dataclass(frozen=True)
class MultiDispatchWitnessExport:
    root: Path
    journal_sha256: str
    manifest_sha256: str
    case_ids: tuple[str, ...]
    selected_case_id: str | None


@dataclass(frozen=True)
class UnverifiedMultiDispatchWitness:
    journal_sha256: str
    case_ids: tuple[str, ...]
    selected_case_id: str | None
    source_hint: dict
    claimed_snapshot: dict
    raw_reviews: tuple[tuple[str, bytes | None], ...]
    claimed_review_validations: tuple[dict, ...]
    claimed_rows: tuple[dict, ...]
    claimed_report: dict
    manifest_sha256: str

    @property
    def verification_status(self) -> str:
        return "unverified"


def _fresh_root(root):
    root = Path(root).absolute()
    _plain_path(root)
    if root.exists():
        raise PreregistrationError("multi_dispatch_witness_requires_fresh_root")
    return root


def _read_regular(path):
    _plain_path(path)
    try:
        if not stat.S_ISREG(path.lstat().st_mode):
            raise PreregistrationError("multi_dispatch_witness_requires_regular_file")
        with path.open("rb") as fh:
            if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                raise PreregistrationError("multi_dispatch_witness_requires_regular_file")
            data = fh.read(MAX_ARTIFACT + 1)
    except FileNotFoundError as exc:
        raise PreregistrationError("multi_dispatch_witness_missing_required_file") from exc
    if len(data) > MAX_ARTIFACT:
        raise PreregistrationError("multi_dispatch_witness_artifact_bound_exceeded")
    ArtifactStore.reference(data)
    return data


def _write_regular(path, data):
    if len(data) > MAX_ARTIFACT:
        raise PreregistrationError("multi_dispatch_witness_artifact_bound_exceeded")
    ArtifactStore.reference(data)
    _plain_path(path)
    with path.open("xb") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            raise PreregistrationError("multi_dispatch_witness_requires_regular_file")
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    if _read_regular(path) != data:
        raise PreregistrationError("multi_dispatch_witness_raw_readback_mismatch")


def _bounded_bundle(files):
    if len(files) > MAX_FILES or sum(len(raw) for raw in files.values()) > MAX_TOTAL_BYTES:
        raise PreregistrationError("multi_dispatch_witness_bundle_bound_exceeded")
    for raw in files.values():
        ArtifactStore.reference(raw)


def _selection(selected, ids):
    if selected is not None and (type(selected) is not str or selected not in ids):
        raise PreregistrationError("multi_dispatch_witness_selection_not_in_full_roster")


def export_multi_dispatch_witness(root, prepared, *, recording_authority,
        source_authority, review_authority=None, selected_case_id=None) -> MultiDispatchWitnessExport:
    """Freshly verify original authorities, then copy that same raw acquisition.

    Root and its parents are a caller-controlled output boundary, with no
    overwrite/resume or claim of secure multiwriter filesystem isolation.
    """
    root = _fresh_root(root)
    material = _acquire_verified_recording(prepared, recording_authority=recording_authority,
        source_authority=source_authority, review_authority=review_authority)
    published = material.published
    ids = tuple(row.case_id for row in published.recording.report.cases)
    _selection(selected_case_id, ids)
    manifest = {"schema_version": SCHEMA, "verification_status": "unverified",
        "case_ids": list(ids), "selected_case_id": selected_case_id,
        "source_hint": {"repository": published.repository, "repository_id": published.repository_id,
            "receipt_commit": published.receipt_commit, "run_id": published.run_id,
            "attempt": published.attempt, "job_id": published.job_id,
            "publication_sha256": published.publication_sha256, "location": asdict(published.location)},
        "journal": {"path": "journal.jsonl", "ref": ArtifactStore.reference(material.journal)},
        "artifacts": [{"path": "artifacts/" + name, "ref": ArtifactStore.reference(raw)}
                      for name, raw in material.artifacts]}
    manifest_bytes = encoded(manifest)
    files = {"artifacts/" + name: raw for name, raw in material.artifacts}
    files.update({"journal.jsonl": material.journal, "README.md": README, "manifest.json": manifest_bytes})
    _bounded_bundle(files)
    _fresh_root(root)
    _mkdir(root, exist_ok=False)
    _mkdir(root / "artifacts", exist_ok=False)
    for name, raw in material.artifacts:
        _write_regular(root / "artifacts" / name, raw)
    _sync_directory(root / "artifacts")
    _write_regular(root / "journal.jsonl", material.journal)
    _write_regular(root / "README.md", README)
    # Final marker only follows complete raw writes and readbacks. Failure leaves
    # this fresh root intact and forbids resuming it as a completed export.
    _write_regular(root / "manifest.json", manifest_bytes)
    _sync_directory(root)
    inspect_multi_dispatch_witness(root)
    return MultiDispatchWitnessExport(root, published.recording.journal_sha256,
        digest(manifest_bytes), ids, selected_case_id)


def _inventory(root):
    _plain_path(root)
    try:
        mode = root.lstat().st_mode
    except FileNotFoundError as exc:
        raise PreregistrationError("multi_dispatch_witness_missing_required_root") from exc
    if not stat.S_ISDIR(mode):
        raise PreregistrationError("multi_dispatch_witness_requires_plain_directory")
    paths = set()
    for entry in root.iterdir():
        _plain_path(entry)
        if entry.name == "artifacts":
            if not stat.S_ISDIR(entry.lstat().st_mode):
                raise PreregistrationError("multi_dispatch_witness_requires_plain_artifact_directory")
            for artifact in entry.iterdir():
                _plain_path(artifact)
                if (re.fullmatch(r"[0-9a-f]{64}", artifact.name) is None
                        or not stat.S_ISREG(artifact.lstat().st_mode)):
                    raise PreregistrationError("multi_dispatch_witness_invalid_artifact_path")
                paths.add("artifacts/" + artifact.name)
                if len(paths) > MAX_FILES:
                    raise PreregistrationError("multi_dispatch_witness_bundle_bound_exceeded")
        elif entry.name in {"manifest.json", "README.md", "journal.jsonl"} and stat.S_ISREG(entry.lstat().st_mode):
            paths.add(entry.name)
        else:
            raise PreregistrationError("multi_dispatch_witness_unexpected_path")
        if len(paths) > MAX_FILES:
            raise PreregistrationError("multi_dispatch_witness_bundle_bound_exceeded")
    if not {"manifest.json", "README.md", "journal.jsonl"}.issubset(paths) or not (root / "artifacts").is_dir():
        raise PreregistrationError("multi_dispatch_witness_incomplete_inventory")
    return paths


def _hint(raw):
    mapping(raw, "unverified J location hint", {"repository", "repository_id", "receipt_commit",
        "run_id", "attempt", "job_id", "publication_sha256", "location"})
    if type(raw["repository"]) is not str or re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", raw["repository"]) is None:
        raise PreregistrationError("multi_dispatch_witness_invalid_repository_hint")
    for name in ("repository_id", "run_id", "attempt", "job_id"):
        integer(raw[name], "unverified " + name, minimum=1)
    commit(raw["receipt_commit"], "unverified receipt commit")
    sha256(raw["publication_sha256"], "unverified publication hint")
    mapping(raw["location"], "unverified J path hint", {"journal_path", "journal_sha256", "artifacts_prefix"})
    for name in ("journal_path", "artifacts_prefix"):
        _artifact_path(raw["location"][name])
    sha256(raw["location"]["journal_sha256"], "unverified raw J hint")


def _claimed_roster(value, ids):
    cases = value.get("cases")
    if (type(cases) is not list or any(type(row) is not dict for row in cases)
            or [row.get("case_id") for row in cases] != ids):
        raise PreregistrationError("multi_dispatch_witness_claimed_roster_mismatch")


def inspect_multi_dispatch_witness(root) -> UnverifiedMultiDispatchWitness:
    """Read strict bounded raw structure, never obtain authority or adjudicate.

    Even coherently replaced contents remain unverified. Every verdict, native
    observation, review/provenance and headline in this result is a saved claim.
    """
    try:
        return _inspect_raw_witness(root)
    except DeclarationError as exc:
        raise PreregistrationError("multi_dispatch_witness_invalid_structure") from exc


def _inspect_raw_witness(root):
    root = Path(root).absolute()
    paths = _inventory(root)
    files, total = {}, 0
    for path in sorted(paths):
        raw = _read_regular(root / path)
        total += len(raw)
        if total > MAX_TOTAL_BYTES:
            raise PreregistrationError("multi_dispatch_witness_bundle_bound_exceeded")
        files[path] = raw
    if files["README.md"] != README:
        raise PreregistrationError("multi_dispatch_witness_readme_mismatch")
    manifest = json_mapping(files["manifest.json"], "unverified witness manifest")
    mapping(manifest, "unverified witness manifest", {"schema_version", "verification_status", "case_ids",
        "selected_case_id", "source_hint", "journal", "artifacts"})
    if manifest["schema_version"] != SCHEMA or manifest["verification_status"] != "unverified":
        raise PreregistrationError("multi_dispatch_witness_unverified_schema_required")
    ids = manifest["case_ids"]
    entries = read_multi_dispatch_journal(files["journal.jsonl"], ids)
    _selection(manifest["selected_case_id"], ids)
    _hint(manifest["source_hint"])
    mapping(manifest["journal"], "unverified journal inventory", {"path", "ref"})
    artifact_ref(manifest["journal"]["ref"], present=True)
    if (manifest["journal"]["path"] != "journal.jsonl"
            or manifest["journal"]["ref"] != ArtifactStore.reference(files["journal.jsonl"])
            or manifest["source_hint"]["location"]["journal_sha256"] != digest(files["journal.jsonl"])):
        raise PreregistrationError("multi_dispatch_witness_journal_raw_identity_mismatch")
    inventory = manifest["artifacts"]
    if type(inventory) is not list or len(inventory) > MAX_FILES:
        raise PreregistrationError("multi_dispatch_witness_invalid_artifact_inventory")
    by_hash, order = {}, []
    for item in inventory:
        mapping(item, "unverified artifact inventory item", {"path", "ref"})
        artifact_ref(item["ref"], present=True)
        name = item["ref"]["sha256"]
        if item["path"] != "artifacts/" + name or name in by_hash:
            raise PreregistrationError("multi_dispatch_witness_duplicate_or_invalid_artifact_inventory")
        raw = files.get(item["path"])
        if raw is None or ArtifactStore.reference(raw) != item["ref"]:
            raise PreregistrationError("multi_dispatch_witness_artifact_raw_identity_mismatch")
        by_hash[name] = raw
        order.append(name)
    if order != sorted(order) or paths != {"manifest.json", "README.md", "journal.jsonl", *["artifacts/" + name for name in by_hash]}:
        raise PreregistrationError("multi_dispatch_witness_inventory_closure_mismatch")
    used = set()

    def read(ref):
        artifact_ref(ref)
        if ref["state"] == "missing":
            return None
        raw = by_hash.get(ref["sha256"])
        if raw is None or ArtifactStore.reference(raw) != ref:
            raise PreregistrationError("multi_dispatch_witness_referenced_artifact_mismatch")
        used.add(ref["sha256"])
        return raw

    snapshot = json_mapping(read(entries[0]["payload"]["snapshot"]), "unverified saved snapshot")
    _claimed_roster(snapshot, ids)
    reviews, validations, rows = [], [], []
    for index, cid in enumerate(ids):
        review = entries[1 + index * 2]["payload"]
        reviews.append((cid, read(review["raw_review"])))
        validation = json_mapping(read(review["validation"]), "unverified saved review validation")
        row = json_mapping(read(entries[2 + index * 2]["payload"]["row"]), "unverified saved row")
        if validation.get("case_id") != cid or row.get("case_id") != cid:
            raise PreregistrationError("multi_dispatch_witness_claimed_case_identity_mismatch")
        validations.append(validation)
        rows.append(row)
    report = json_mapping(read(entries[-1]["payload"]["report"]), "unverified saved report")
    _claimed_roster(report, ids)
    if (type(report.get("frozen_case_count")) is not int or report["frozen_case_count"] != len(ids)
            or type(report.get("snapshot")) is not dict):
        raise PreregistrationError("multi_dispatch_witness_claimed_denominator_mismatch")
    _claimed_roster(report["snapshot"], ids)
    if used != set(by_hash):
        raise PreregistrationError("multi_dispatch_witness_unreferenced_artifact")
    return UnverifiedMultiDispatchWitness(digest(files["journal.jsonl"]), tuple(ids), manifest["selected_case_id"],
        manifest["source_hint"], snapshot, tuple(reviews), tuple(validations), tuple(rows), report,
        digest(files["manifest.json"]))
