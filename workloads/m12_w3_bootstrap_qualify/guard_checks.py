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


if __name__ == "__main__":
    unittest.main()
