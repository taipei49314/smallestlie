"""Pinned prose and case-coverage declarations must remain distinct."""

from copy import deepcopy
import hashlib
from pathlib import Path
import shutil

import pytest
import yaml

from smallestlie.adapters.checkwash import PINNED_SHA256, PINNED_SOURCE_REVISION, PINNED_VERSION
from smallestlie.adjudication.residuals import PINNED_INDEX_SHA256, ResidualSourceError, load_residual_catalog

ROOT = Path(__file__).resolve().parents[2]
INDEX = "catalogs/residual-rows-checkwash-v0.6.0.json"


def load(path, **changes):
    kwargs = dict(expected_engine_version=PINNED_VERSION, expected_engine_sha256=PINNED_SHA256,
                  expected_source_revision=PINNED_SOURCE_REVISION, expected_index_sha256=PINNED_INDEX_SHA256)
    kwargs.update(changes)
    return load_residual_catalog(path, **kwargs)


def copy_index(tmp_path):
    (tmp_path / "catalogs").mkdir()
    shutil.copytree(ROOT / "provenance", tmp_path / "provenance")
    path = tmp_path / INDEX
    shutil.copyfile(ROOT / INDEX, path)
    return path


def test_spec_two_hop_and_closed_or_mixed_rows_keep_different_meanings():
    catalog = load(ROOT / INDEX)
    assert catalog["coverage"] == "partial"
    rows = catalog["entries_by_id"]
    assert rows["SPEC:SUBJECT_NORMALIZED:two-hop"]["status"] == "documented_residual"
    assert rows["THREATMODEL:5"]["status"] == "closed"
    assert rows["THREATMODEL:108"]["status"] == "mixed"
    assert rows["THREATMODEL:109"]["status"] == "mixed"
    assert rows["THREATMODEL:117"]["status"] == "mixed"
    assert "matched_residual" not in catalog


@pytest.mark.parametrize("problem", ["closed_as_residual", "source_substitution"])
def test_self_reported_hashes_cannot_replace_the_reviewed_index(tmp_path, problem):
    path = copy_index(tmp_path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if problem == "closed_as_residual":
        next(row for row in raw["entries"] if row["id"] == "THREATMODEL:5")["status"] = "documented_residual"
    else:
        source = raw["sources"][0]
        data = b"substituted source\n"
        (tmp_path / source["path"]).write_bytes(data)
        source["sha256"] = hashlib.sha256(data).hexdigest()
        source["git_blob"] = hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    with pytest.raises(ResidualSourceError, match="reviewed residual index digest"):
        load(path)


def test_parser_cannot_observe_a_replacement_after_digest_check(tmp_path, monkeypatch):
    path = copy_index(tmp_path)
    authenticated = path.read_bytes()
    changed = yaml.safe_load(authenticated.decode("utf-8"))
    next(row for row in changed["entries"] if row["id"] == "THREATMODEL:5")["status"] = "documented_residual"
    replacement = yaml.safe_dump(changed).encode("utf-8")
    original_read = Path.read_bytes
    reads = []

    def replaced_read(candidate):
        if candidate == path:
            reads.append(candidate)
            return authenticated if len(reads) == 1 else replacement
        return original_read(candidate)

    monkeypatch.setattr(Path, "read_bytes", replaced_read)
    catalog = load(path)
    assert catalog["entries_by_id"]["THREATMODEL:5"]["status"] == "closed"
    assert len(reads) == 1


@pytest.mark.parametrize("field,value", [("expected_engine_version", "0.4.2"),
                                        ("expected_engine_sha256", "0" * 64),
                                        ("expected_source_revision", "0" * 40)])
def test_sources_cannot_be_reused_under_a_different_pin(field, value):
    with pytest.raises(ResidualSourceError, match="pin"):
        load(ROOT / INDEX, **{field: value})


def test_source_newline_change_invalidates_record(tmp_path):
    path = copy_index(tmp_path)
    source = tmp_path / "provenance/checkwash-v0.6.0/SPEC.md"
    source.write_bytes(source.read_bytes().replace(b"\n", b"\r\n"))
    with pytest.raises(ResidualSourceError, match="digest mismatch"):
        load(path)


@pytest.mark.parametrize("problem", ["quote", "span", "bool_span", "unknown_source", "duplicate", "escape", "blob"])
def test_broken_statement_locator_is_not_accepted(tmp_path, problem):
    path = copy_index(tmp_path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    row = raw["entries"][0]
    if problem == "quote":
        row["quote_sha256"] = "0" * 64
    elif problem == "span":
        row["end_line"] = 999999
    elif problem == "bool_span":
        row["start_line"] = True
    elif problem == "unknown_source":
        row["source"] = "missing"
    elif problem == "duplicate":
        raw["entries"].append(deepcopy(row))
    elif problem == "escape":
        raw["sources"][0]["path"] = "../outside"
    else:
        raw["sources"][0]["git_blob"] = "0" * 40
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    # Authorize the test-only malformed index bytes so deeper validation is exercised.
    with pytest.raises(ResidualSourceError):
        load(path, expected_index_sha256=hashlib.sha256(path.read_bytes()).hexdigest())


@pytest.mark.parametrize("body", [None, "[not-a-mapping]\n", "engine: [\n", "engine: a\nengine: b\n"])
def test_missing_or_malformed_manifest_has_one_error_contract(tmp_path, body):
    path = tmp_path / "missing.yaml"
    if body is not None:
        path.write_text(body, encoding="utf-8")
    expected = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else PINNED_INDEX_SHA256
    with pytest.raises(ResidualSourceError):
        load(path, expected_index_sha256=expected)
