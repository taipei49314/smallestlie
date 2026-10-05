"""Proposed workloads/m12_w3_bootstrap_qualify/guard_checks.py.

Actual bootstrap entry invokes this stdlib-only process before restoration.
No product package, fixtures, engine, runner, semantic case or network imports.
NOT_RUN in drafting session; use the separately approved pool workload only.
"""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

ENTRY = Path(sys.argv.pop(1)).resolve()
spec = importlib.util.spec_from_file_location("w3_bootstrap_guards_subject", ENTRY)
subject = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = subject
spec.loader.exec_module(subject)


class RestorationGuards(unittest.TestCase):
    def setUp(self):
        private_tmp = Path(os.environ["TMP"]).resolve()
        if not private_tmp.is_dir() or private_tmp != Path(os.environ["TEMP"]).resolve():
            raise RuntimeError("bootstrap guards require the existing job-private TMP/TEMP")
        self.private_tmp = private_tmp
        self.directory = tempfile.TemporaryDirectory(prefix="w3-bootstrap-guards-", dir=private_tmp)
        self.root = Path(self.directory.name)

    def tearDown(self):
        if not self.root.resolve().is_relative_to(self.private_tmp):
            raise RuntimeError("guard cleanup escaped the job-private temp root")
        self.directory.cleanup()

    def archive(self, members, name="image.zip"):
        path = self.root / name
        with zipfile.ZipFile(path, "x", compression=zipfile.ZIP_DEFLATED) as package:
            for name, raw, mode in members:
                info = zipfile.ZipInfo(name)
                info.external_attr = mode << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                package.writestr(info, raw)
        return path

    def map(self, mapping):
        return subject.canonical({name: subject.sha(raw) for name, raw in mapping.items()})

    def test_scoped_original_members_preserve_raw_bytes(self):
        values = {"node_modules/@scope/pkg/data.bin": b"\x00\xff\r\n",
                  "node_modules/@scope/pkg/file with space.js": b"line\r\n"}
        archive = self.archive([(name, raw, stat.S_IFREG | 0o644) for name, raw in values.items()])
        restored = self.root / "restored"
        subject.restore_image(archive, restored, self.map(values), 100_000)
        self.assertEqual(subject.full_map(restored, 100_000), {key: subject.sha(raw) for key, raw in values.items()})
        self.assertEqual((restored / "node_modules/@scope/pkg/data.bin").read_bytes(), b"\x00\xff\r\n")

    def test_unsafe_windows_names_refused(self):
        for name in ("../escape", "/absolute", "a\\b", "file:stream", "CON", "x/NUL.txt",
                     "x./file", "x /file", "x//file", "x/.git/file"):
            with self.subTest(name=name):
                with self.assertRaises(subject.ProposalRefusal):
                    subject.relative(name)

    def test_symlink_archive_member_is_not_regular(self):
        archive = self.archive([("file", b"target", stat.S_IFLNK | 0o777)])
        with self.assertRaisesRegex(subject.ProposalRefusal, "nonregular"):
            subject.restore_image(archive, self.root / "restored", self.map({"file": b"target"}), 100_000)

    def test_unbound_directory_refused_after_full_restore(self):
        archive = self.archive([("file", b"raw", stat.S_IFREG | 0o644),
                                ("unbound/", b"", stat.S_IFDIR | 0o755)])
        with self.assertRaisesRegex(subject.ProposalRefusal, "unbound/empty"):
            subject.restore_image(archive, self.root / "restored", self.map({"file": b"raw"}), 100_000)

    def test_casefold_alias_map_refused(self):
        with self.assertRaisesRegex(subject.ProposalRefusal, "aliases"):
            subject.expected_map(self.map({"one.js": b"one", "ONE.js": b"two"}), 100_000)

    def test_expansion_bound_does_not_filter_original_members(self):
        archive = self.archive([("file", b"raw input", stat.S_IFREG | 0o644)])
        with self.assertRaises(subject.ProposalRefusal):
            subject.restore_image(archive, self.root / "restored", self.map({"file": b"raw input"}), 2)

    def parts(self):
        raw_root = self.root / "input"
        (raw_root / "w3-freeze").mkdir(parents=True)
        values = [("image-0000.zip.part", b"first\r\n"), ("image-0001.zip.part", b"\x00\xffsecond")]
        chunks = []
        for name, raw in values:
            (raw_root / "w3-freeze" / name).write_bytes(raw)
            chunks.append({"path": name, "bytes": len(raw), "sha256": subject.sha(raw)})
        whole = b"".join(raw for _, raw in values)
        return raw_root, {"chunks": chunks, "archive_sha256": subject.sha(whole), "raw_zip_bytes": len(whole)}, whole

    def test_ordered_parts_and_swapped_order_are_distinct(self):
        raw_root, record, whole = self.parts()
        result = self.root / "assembled.zip"
        subject.reassemble(raw_root, record, result)
        self.assertEqual(result.read_bytes(), whole)
        record["chunks"] = list(reversed(record["chunks"]))
        with self.assertRaisesRegex(subject.ProposalRefusal, "whole archive"):
            subject.reassemble(raw_root, record, self.root / "reversed.zip")

    def test_part_drift_refuses_and_preserves_partial_file(self):
        raw_root, record, _ = self.parts()
        (raw_root / "w3-freeze" / record["chunks"][1]["path"]).write_bytes(b"changed")
        destination = self.root / "failed.zip"
        with self.assertRaisesRegex(subject.ProposalRefusal, "part length/hash"):
            subject.reassemble(raw_root, record, destination)
        self.assertTrue(destination.exists())
        self.assertEqual(destination.read_bytes(), b"first\r\n")

    def test_duplicate_part_descriptor_cannot_reuse_raw_source(self):
        raw_root, record, _ = self.parts()
        record["chunks"][1] = dict(record["chunks"][0])
        with self.assertRaisesRegex(subject.ProposalRefusal, "duplicate part"):
            subject.reassemble(raw_root, record, self.root / "duplicate.zip")

    def original_manifest(self):
        raw_root = self.root / "receipt"
        raw_root.mkdir()
        raw = b"complete original\r\n"
        (raw_root / "file.raw").write_bytes(raw)
        manifest = {"schema_version": 1, "status": "preserved", "context": {
            "GITHUB_RUN_ID": "37207000468", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_SHA": "3cce1bc37ae830fce9f64a748f7392659f5b6698",
            "COMPUTERNAME": subject.HOST, "EC_JOB_STATUS": "success"}, "files": [
            {"path": "file.raw", "bytes": len(raw), "sha256": subject.sha(raw)}]}
        (raw_root / "ec-publication.json").write_bytes(subject.canonical(manifest))
        return raw_root

    def test_publication_inventory_rejects_extra_raw_member(self):
        raw_root = self.original_manifest()
        subject.verify_original_publication(raw_root)
        (raw_root / "extra.raw").write_bytes(b"unrecorded")
        with self.assertRaisesRegex(subject.ProposalRefusal, "drops/adds"):
            subject.verify_original_publication(raw_root)

    def test_publication_member_raw_drift_refused(self):
        raw_root = self.original_manifest()
        (raw_root / "file.raw").write_bytes(b"changed original")
        with self.assertRaisesRegex(subject.ProposalRefusal, "raw member differs"):
            subject.verify_original_publication(raw_root)


class ImageScannerGuards(unittest.TestCase):
    # This independent class uses only the common temp setup, not a product
    # importer, frozen utility binding, native runner or formal fixture.
    setUp = RestorationGuards.setUp
    tearDown = RestorationGuards.tearDown

    def scan(self, root, **bounds):
        return subject.scan_image(root, maximum=bounds.pop("maximum", 100_000),
                                  path_rule=subject.relative, **bounds)

    def image(self):
        root = self.root / "scanner-image"
        leaf = root / "node_modules/@scope/pkg/file with space.bin"
        leaf.parent.mkdir(parents=True)
        leaf.write_bytes(b"\x00\xff\r\n")
        return root, leaf

    def spy_reads(self, *, short_limit=None):
        original = subject.Path.open
        requests = []
        class ReadSpy:
            def __init__(self, stream):
                self.stream = stream

            def __enter__(self):
                self.stream.__enter__()
                return self

            def __exit__(self, *args):
                return self.stream.__exit__(*args)

            def fileno(self):
                return self.stream.fileno()

            def read(self, maximum):
                requests.append(maximum)
                return self.stream.read(maximum if short_limit is None
                                        else min(maximum, short_limit))

        def opened(path, *args, **kwargs):
            return ReadSpy(original(path, *args, **kwargs))
        return mock.patch.object(subject.Path, "open", new=opened), requests

    def test_scanner_chunked_eof_preserves_all_raw_bytes_and_short_reads(self):
        _, leaf = self.image()
        raw = b"\x00\xff\r\n" * (subject.SCAN_READ_CHUNK // 4 + 2)
        leaf.write_bytes(raw)
        for short_limit in (None, 4093):
            spy, requests = self.spy_reads(short_limit=short_limit)
            totals = subject.ScanTotals()
            with spy:
                actual = subject.scan_read(leaf, 256 * 1024 * 1024, totals=totals)
            self.assertEqual(actual, raw)
            self.assertEqual(totals.raw_bytes, len(raw))
            self.assertEqual(totals.samples["raw_read"]["calls"], len(requests))
            self.assertTrue(requests)
            self.assertTrue(all(0 < request <= 64 * 1024 for request in requests))
            self.assertEqual(requests[0], 64 * 1024)

    def test_scanner_exact_and_zero_quota_still_reads_eof_sentinel(self):
        _, leaf = self.image()
        raw = b"\x00\xff\r\n" * (subject.SCAN_READ_CHUNK // 4 + 2)
        leaf.write_bytes(raw)
        spy, requests = self.spy_reads()
        with spy:
            self.assertEqual(subject.scan_read(leaf, len(raw)), raw)
        self.assertEqual(requests[-1], 1)
        with self.assertRaisesRegex(subject.ProposalRefusal, "byte quota"):
            subject.scan_read(leaf, len(raw) - 1)
        with self.assertRaisesRegex(subject.ProposalRefusal, "byte quota"):
            subject.scan_read(leaf, 0)
        leaf.write_bytes(b"")
        spy, requests = self.spy_reads()
        with spy:
            self.assertEqual(subject.scan_read(leaf, 0), b"")
        self.assertEqual(requests, [1])

    def test_scanner_totals_keep_full_map_and_actual_read_bytes(self):
        root, leaf = self.image()
        extra = root / "extra.raw"
        extra.write_bytes(b"extra")
        totals = subject.ScanTotals()
        actual = self.scan(root, totals=totals)
        self.assertEqual(actual, {leaf.relative_to(root).as_posix(): subject.sha(b"\x00\xff\r\n"),
                                  "extra.raw": subject.sha(b"extra")})
        self.assertEqual(totals.raw_bytes, len(b"\x00\xff\r\nextra"))
        self.assertEqual(totals.samples["hash"]["calls"], len(actual))
        self.assertEqual(set(totals.observation()), {"reader", "read_chunk_bytes",
                          "sampled_operations", "observed_raw_bytes", "exhaustive_cost_model"})
        self.assertFalse(totals.observation()["exhaustive_cost_model"])

    def test_scanner_refusal_preserves_totals_without_completion(self):
        root, _ = self.image()
        output = self.root / "refused-scan-observations"
        progress = subject.PrivateProgress(output)
        with self.assertRaisesRegex(subject.ProposalRefusal, "byte quota"):
            progress.measure_scan("guard-map", lambda totals:
                                  self.scan(root, maximum=2, totals=totals))
        records = [json.loads(path.read_bytes()) for path in
                   sorted((output / "private-progress").glob("*.json"))]
        self.assertEqual([record["stage"] for record in records],
                         ["guard-map-started", "guard-map-scan-totals"])
        self.assertEqual(records[-1]["observed_raw_bytes"], 3)
        self.assertFalse(records[-1]["exhaustive_cost_model"])
        self.assertTrue(all(record["formal_execution"] is False for record in records))

    def test_scanner_scoped_raw_map_and_extra_member(self):
        root, leaf = self.image()
        expected = {leaf.relative_to(root).as_posix(): subject.sha(b"\x00\xff\r\n")}
        self.assertEqual(self.scan(root), expected)
        (root / "extra.raw").write_bytes(b"extra")
        self.assertEqual(self.scan(root), {**expected, "extra.raw": subject.sha(b"extra")})

    def test_scanner_rejects_byte_and_file_count_quota(self):
        root, _ = self.image()
        with self.assertRaisesRegex(subject.ProposalRefusal, "byte quota"):
            self.scan(root, maximum=2)
        (root / "extra.raw").write_bytes(b"x")
        with self.assertRaisesRegex(subject.ProposalRefusal, "file count"):
            self.scan(root, file_count=1)

    def test_scanner_physical_empty_directory_refused(self):
        root, _ = self.image()
        (root / "unbound").mkdir()
        with self.assertRaisesRegex(subject.ProposalRefusal, "unbound"):
            self.scan(root)
        self.assertTrue(self.scan(root, physical=False))

    def test_scanner_native_hardlink_refused(self):
        root, leaf = self.image()
        os.link(leaf, root / "hardlinked.raw")
        with self.assertRaisesRegex(subject.ProposalRefusal, "hardlinked"):
            self.scan(root)

    def test_scanner_fresh_reparse_and_symlink_metadata_refused(self):
        root, leaf = self.image()
        original = subject.os.lstat
        for changed in ({"st_file_attributes": 0x400}, {"st_mode": stat.S_IFLNK | 0o777}):
            def hostile(path, *args, **kwargs):
                value = original(path, *args, **kwargs)
                if Path(path) != leaf:
                    return value
                fields = {name: getattr(value, name) for name in
                          ("st_mode", "st_nlink", "st_ino", "st_dev", "st_size", "st_mtime_ns")}
                return type("ObservedUnsafeMetadata", (), {**fields, **changed})()
            with mock.patch.object(subject.os, "lstat", side_effect=hostile):
                with self.assertRaisesRegex(subject.ProposalRefusal, "linked/reparse"):
                    self.scan(root)

    def test_scanner_opened_identity_mismatch_refused(self):
        _, leaf = self.image()
        original = subject.os.fstat
        def other_identity(fd):
            value = original(fd)
            fields = {name: getattr(value, name) for name in
                      ("st_mode", "st_nlink", "st_ino", "st_dev", "st_size", "st_mtime_ns")}
            return type("ObservedOtherFile", (), {**fields, "st_ino": value.st_ino + 1})()
        with mock.patch.object(subject.os, "fstat", side_effect=other_identity):
            with self.assertRaisesRegex(subject.ProposalRefusal, "identity differs"):
                subject.scan_read(leaf, 100_000)

    def test_scanner_walk_removal_and_type_replacement_refused(self):
        root, leaf = self.image()
        original = subject.os.walk
        for operation in ("remove", "directory"):
            def changed_walk(*args, **kwargs):
                for current, directories, files in original(*args, **kwargs):
                    if Path(current) == leaf.parent:
                        leaf.unlink()
                        if operation == "directory":
                            leaf.mkdir()
                    yield current, directories, files
            with mock.patch.object(subject.os, "walk", side_effect=changed_walk):
                with self.assertRaises((subject.ProposalRefusal, FileNotFoundError)):
                    self.scan(root)
            if leaf.is_dir():
                leaf.rmdir()
            leaf.write_bytes(b"\x00\xff\r\n")

    def test_scanner_walk_error_is_not_ignored(self):
        root, _ = self.image()
        def denied_walk(*args, **kwargs):
            kwargs["onerror"](PermissionError("observed denied directory"))
            yield root, [], []
        with mock.patch.object(subject.os, "walk", side_effect=denied_walk):
            with self.assertRaises(PermissionError):
                self.scan(root)

    def test_scanner_casefold_alias_refused(self):
        root, leaf = self.image()
        original = subject.os.walk
        def duplicate_walk(*args, **kwargs):
            for current, directories, files in original(*args, **kwargs):
                if Path(current) == leaf.parent:
                    files = [*files, leaf.name.upper()]
                yield current, directories, files
        with mock.patch.object(subject.os, "walk", side_effect=duplicate_walk):
            with self.assertRaisesRegex(subject.ProposalRefusal, "casefold"):
                self.scan(root)

    def test_scanner_changed_opened_metadata_refused(self):
        _, leaf = self.image()
        original = subject.os.fstat
        seen = []
        def changed_metadata(fd):
            value = original(fd)
            seen.append(fd)
            if len(seen) == 1:
                return value
            fields = {name: getattr(value, name) for name in
                      ("st_mode", "st_nlink", "st_ino", "st_dev", "st_size", "st_mtime_ns")}
            return type("ObservedChangedFile", (), {**fields, "st_size": value.st_size + 1})()
        with mock.patch.object(subject.os, "fstat", side_effect=changed_metadata):
            with self.assertRaisesRegex(subject.ProposalRefusal, "changed during read"):
                subject.scan_read(leaf, 100_000)

    def test_scanner_post_read_path_identity_mismatch_refused(self):
        _, leaf = self.image()
        original = subject.os.lstat
        seen = []
        def replaced_path(path, *args, **kwargs):
            value = original(path, *args, **kwargs)
            if Path(path) != leaf:
                return value
            seen.append(path)
            if len(seen) == 1:
                return value
            fields = {name: getattr(value, name) for name in
                      ("st_mode", "st_nlink", "st_ino", "st_dev", "st_size", "st_mtime_ns")}
            return type("ObservedReplacedPath", (), {**fields, "st_ino": value.st_ino + 1})()
        with mock.patch.object(subject.os, "lstat", side_effect=replaced_path):
            with self.assertRaisesRegex(subject.ProposalRefusal, "path identity changed"):
                subject.scan_read(leaf, 100_000)

    def test_scanner_unidentified_handle_refused(self):
        _, leaf = self.image()
        original = subject.os.fstat
        def unidentified(fd):
            value = original(fd)
            fields = {name: getattr(value, name) for name in
                      ("st_mode", "st_nlink", "st_ino", "st_dev", "st_size", "st_mtime_ns")}
            return type("ObservedUnidentifiedHandle", (), {**fields, "st_ino": 0})()
        with mock.patch.object(subject.os, "fstat", side_effect=unidentified):
            with self.assertRaisesRegex(subject.ProposalRefusal, "unidentified"):
                subject.scan_read(leaf, 100_000)

    def test_scanner_ancestor_reparse_is_checked_again_at_open(self):
        _, leaf = self.image()
        original = subject.os.lstat
        seen = []
        def changed_ancestor(path, *args, **kwargs):
            value = original(path, *args, **kwargs)
            if Path(path) != leaf.parent:
                return value
            seen.append(path)
            if len(seen) == 1:
                return value
            fields = {name: getattr(value, name) for name in
                      ("st_mode", "st_nlink", "st_ino", "st_dev", "st_size", "st_mtime_ns")}
            return type("ObservedChangedAncestor", (), {**fields, "st_file_attributes": 0x400})()
        with mock.patch.object(subject.os, "lstat", side_effect=changed_ancestor):
            subject.scan_plain(leaf)
            with self.assertRaisesRegex(subject.ProposalRefusal, "linked/reparse"):
                subject.scan_read(leaf, 100_000)


if __name__ == "__main__":
    unittest.main()
