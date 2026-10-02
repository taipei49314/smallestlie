"""Verify pinned statement sources without declaring a case covered by them."""

from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
import re
from typing import Any

from smallestlie.attacks.adjudication import (
    DeclarationError, choice, mapping, relative_path, sha256, string,
)
from smallestlie.attacks.schema import AttackSchemaError, load_mapping_bytes

STATUSES = {"documented_residual", "closed", "out_of_scope", "narrowed", "mixed"}
# Reviewed index bytes bind source blobs AND interpretations to the engine pin.
# This value must never be taken from the untrusted case/catalog being loaded.
PINNED_INDEX_SHA256 = "fc8bab95563fd3b38ae8eb1e6949d38429aecc0ecc4f9625c5d2371344c90bdf"


class ResidualSourceError(ValueError):
    pass


def _confined(root: Path, ref: Any) -> Path:
    relative_path(ref, "source.path")
    path = (root / ref).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ResidualSourceError("snapshot source escapes root")
    if not path.is_file():
        raise ResidualSourceError(f"snapshot source missing: {ref}")
    return path


def load_residual_catalog(
    path: str | Path, *, expected_engine_version: str, expected_engine_sha256: str,
    expected_source_revision: str, expected_index_sha256: str,
    snapshot_root: str | Path | None = None,
) -> dict[str, Any]:
    """Return verified source/index declarations; coverage remains case-specific."""
    manifest_path = Path(path)
    root = Path(snapshot_root) if snapshot_root else manifest_path.parent.parent
    try:
        sha256(expected_index_sha256, "expected index digest")
        index_bytes = manifest_path.read_bytes()
        if hashlib.sha256(index_bytes).hexdigest() != expected_index_sha256:
            raise ResidualSourceError("reviewed residual index digest mismatch")
        raw = load_mapping_bytes(index_bytes, source_path=str(manifest_path))
        mapping(raw, "residual catalog", {"schema_version", "coverage", "engine", "sources", "entries"})
        choice(raw["schema_version"], "residual schema", {"smallestlie.residual-catalog/v1"})
        choice(raw["coverage"], "index coverage", {"partial"})
        engine = mapping(raw["engine"], "engine", {"repository", "version", "artifact_sha256", "source_revision"})
        choice(engine["repository"], "engine.repository", {"taipei49314/checkwash"})
        sha256(engine["artifact_sha256"], "engine.artifact_sha256")
        if (engine["version"] != expected_engine_version
                or engine["artifact_sha256"] != expected_engine_sha256
                or engine["source_revision"] != expected_source_revision
                or not isinstance(engine["source_revision"], str)
                or not re.fullmatch(r"[0-9a-f]{40}", engine["source_revision"])):
            raise ResidualSourceError("residual sources do not match the expected engine pin")
        if not isinstance(raw["sources"], list) or not raw["sources"]:
            raise ResidualSourceError("sources must be a nonempty list")
        documents: dict[str, list[bytes]] = {}
        for source in raw["sources"]:
            mapping(source, "source", {"id", "path", "sha256", "git_blob"})
            sid = string(source["id"], "source.id")
            if sid in documents:
                raise ResidualSourceError(f"duplicate source: {sid}")
            sha256(source["sha256"], "source.sha256")
            blob = string(source["git_blob"], "source.git_blob")
            if not re.fullmatch(r"[0-9a-f]{40}", blob):
                raise ResidualSourceError("git_blob must be a Git SHA-1 object id")
            data = _confined(root, source["path"]).read_bytes()
            if hashlib.sha256(data).hexdigest() != source["sha256"]:
                raise ResidualSourceError(f"snapshot digest mismatch: {sid}")
            if hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest() != blob:
                raise ResidualSourceError(f"snapshot Git blob mismatch: {sid}")
            documents[sid] = data.splitlines(keepends=True)
        if not isinstance(raw["entries"], list):
            raise ResidualSourceError("entries must be a list")
        entries: dict[str, dict] = {}
        for entry in raw["entries"]:
            mapping(entry, "entry", {"id", "source", "start_line", "end_line", "quote_sha256",
                                     "status", "status_raw", "coverage", "rationale"})
            eid = string(entry["id"], "entry.id")
            if eid in entries:
                raise ResidualSourceError(f"duplicate entry: {eid}")
            choice(entry["status"], "entry.status", STATUSES)
            for field in ("status_raw", "coverage", "rationale"):
                string(entry[field], f"entry.{field}")
            source_id = string(entry["source"], "entry.source")
            if source_id not in documents:
                raise ResidualSourceError(f"unknown source: {source_id}")
            first, last = entry["start_line"], entry["end_line"]
            lines = documents[source_id]
            if type(first) is not int or type(last) is not int or not 1 <= first <= last <= len(lines):
                raise ResidualSourceError(f"invalid inclusive line span: {eid}")
            sha256(entry["quote_sha256"], "entry.quote_sha256")
            quote = b"".join(lines[first - 1:last])
            if hashlib.sha256(quote).hexdigest() != entry["quote_sha256"]:
                raise ResidualSourceError(f"quote digest mismatch: {eid}")
            if entry["status_raw"] not in quote.decode("utf-8"):
                raise ResidualSourceError(f"raw status absent from source quote: {eid}")
            entries[eid] = deepcopy(entry)
        verified = deepcopy(raw)
        verified["entries_by_id"] = entries
        return verified
    except (DeclarationError, AttackSchemaError, OSError, UnicodeError) as exc:
        raise ResidualSourceError(str(exc)) from exc
