"""W3 bootstrap qualification proposal: restore original sealed inputs, private
-I -B loader, bounded native byte capture/Node version and benign MinGit range.
No W3 fixtures, Checkwash engine, FormalLifecycle, execution authority, publisher
credentials or collector/host-storage/network adoption. Requires separately
reviewed trusted EC preparation prefetch; see companion review. Written only.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import zipfile

HOST = "LAPTOP-50KP71KA"
COLLECTOR_PATH = "campaigns/checkwash-wave-3/contracts/w3_external_collector.py"
COLLECTOR_SHA256 = "ee972284ec1052937afb7ddf078da6e6a28a265e7fec318454ef0cf8eeb0fa29"
MANIFEST_SHA256 = "daf4497f252e141a5d13e2b1e8d461aa590b8089c3006b69703081b24c37c432"
PREP_REPOSITORY = "taipei49314/estate-consolidation"
PREP_COMMIT = "bd5717edac6bec5081dcbb56d4a6c9e1075c0753"
PREP_TREE = "db7d46cbddbe1855c1faccca932d22a3dae514f1"
MAX_FILES = 20_000
MAX_PART = 8_388_608
MAX_ARCHIVE = 256 * 1024 * 1024
IMAGE_BOUNDS = {"python": 100_000_000, "node": 256 * 1024 * 1024,
                "js": 512 * 1024 * 1024}
SCAN_READ_CHUNK = 64 * 1024


class ProposalRefusal(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def strict_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProposalRefusal("duplicate JSON key")
        result[key] = value
    return result


def json_object(raw):
    if type(raw) is not bytes or len(raw) > 10_000_000:
        raise ProposalRefusal("bounded original JSON bytes required")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=strict_pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(
                           ProposalRefusal("nonfinite JSON")))
    if type(value) is not dict:
        raise ProposalRefusal("JSON object required")
    return value


def relative(value):
    # Installation grammar accepts scoped npm packages. Not a receipt grammar.
    if (type(value) is not str or not value or value.startswith("/")
            or any(ord(c) < 32 or c in '\\:<>"|?*' for c in value)):
        raise ProposalRefusal("unsafe restoration path")
    for part in value.split("/"):
        device = part.split(".", 1)[0].upper()
        if (part in {"", ".", ".."} or part.casefold() == ".git"
                or part.endswith((" ", ".")) or device in {"CON", "PRN", "AUX", "NUL"}
                or re.fullmatch(r"(?:COM|LPT)[1-9¹²³]", device)):
            raise ProposalRefusal("unsafe Windows path component")
    return value


def plain(path):
    path = Path(path)
    for item in (*reversed(path.parents), path):
        if item.exists():
            info = item.lstat()
            if (stat.S_ISLNK(info.st_mode)
                    or getattr(info, "st_file_attributes", 0) & 0x400
                    or (item.is_file() and info.st_nlink != 1)):
                raise ProposalRefusal("linked/reparse/hardlinked restoration input")
    return path


def read(path, maximum):
    path = plain(path)
    if not path.is_file() or path.stat().st_size > maximum:
        raise ProposalRefusal("missing or oversized original file")
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ProposalRefusal("original file grew beyond quota")
    return raw


def write_new(path, raw):
    path = plain(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    plain(path.parent)
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    if read(path, len(raw)) != raw:
        raise ProposalRefusal("exclusive write/readback mismatch")
    # This readback is local persistence. No power-loss approval is claimed.


class PrivateProgress:
    """Bounded diagnostic observations, never execution/adoption authority."""

    def __init__(self, out):
        self.root = out / "private-progress"
        self.started = time.monotonic()
        self.sequence = 0

    def emit(self, stage, **observations):
        if not re.fullmatch(r"[a-z0-9-]{1,80}", stage) or self.sequence >= 1024:
            raise ProposalRefusal("private progress exceeds fixed diagnostic budget")
        self.sequence += 1
        record = {**observations, "document_kind": "private-bootstrap-progress-observation",
                  "sequence": self.sequence, "stage": stage,
                  "seconds": time.monotonic() - self.started, "formal_execution": False}
        raw = canonical(record)
        if len(raw) > 4096:
            raise ProposalRefusal("private progress record exceeds fixed byte budget")
        write_new(self.root / (f"{self.sequence:04d}-" + stage + ".json"), raw)

    def measure(self, stage, operation):
        self.emit(stage + "-started")
        value = operation()
        self.emit(stage + "-completed", files=len(value))
        return value

    def measure_scan(self, stage, operation):
        self.emit(stage + "-started")
        totals = ScanTotals()
        try:
            value = operation(totals)
        finally:
            # One fixed-size observation per map, including ordinary refusal.
            # A killed loader may never reach this finally; no completion is
            # fabricated for an interrupted scan.
            self.emit(stage + "-scan-totals", **totals.observation())
        self.emit(stage + "-completed", files=len(value))
        return value


def expected_map(raw, bound):
    mapping = json_object(raw)
    aliases, total_keys = set(), 0
    if not mapping:
        raise ProposalRefusal("empty original installation map")
    for name, digest in mapping.items():
        relative(name)
        total_keys += 1
        if name.casefold() in aliases or not re.fullmatch(r"[0-9a-f]{64}", str(digest)):
            raise ProposalRefusal("installation aliases or invalid raw digest")
        aliases.add(name.casefold())
    if total_keys > MAX_FILES or type(bound) is not int or bound < 1:
        raise ProposalRefusal("bounded installation map required")
    return mapping


def full_map(root, bound):
    root = plain(root)
    result, aliases, observed_dirs, total = {}, set(), set(), 0
    for parent, directories, files in os.walk(root, followlinks=False,
                                             onerror=lambda error: (_ for _ in ()).throw(error)):
        for item in (*directories, *files):
            path = plain(Path(parent) / item)
            name = relative(path.relative_to(root).as_posix())
            if name.casefold() in aliases:
                raise ProposalRefusal("casefold file/directory alias")
            aliases.add(name.casefold())
            if path.is_dir():
                observed_dirs.add(name)
            elif not path.is_file():
                raise ProposalRefusal("nonregular restored input")
        for item in files:
            path = Path(parent) / item
            name = path.relative_to(root).as_posix()
            raw = read(path, min(bound, 128 * 1024 * 1024))
            total += len(raw)
            if total > bound or len(result) >= MAX_FILES:
                raise ProposalRefusal("restored tree exceeds bound")
            result[name] = sha(raw)
    implied_dirs = {"/".join(name.split("/")[:i]) for name in result
                    for i in range(1, len(name.split("/")))}
    if observed_dirs != implied_dirs:
        raise ProposalRefusal("unbound/empty restoration directory")
    return result


class ScanTotals:
    """Diagnostic wall samples of named operations, never authority/cache.

    These buckets are not an exhaustive cost model: walking, validation,
    accumulation, serialization and scheduling also affect the whole map.
    """

    def __init__(self):
        self.samples = {name: {"calls": 0, "seconds": 0.0} for name in
                        ("path_checks", "open", "raw_read", "identity", "hash")}
        self.raw_bytes = 0

    def call(self, name, operation, *args, **kwargs):
        sample = self.samples[name]
        started = time.monotonic()
        try:
            return operation(*args, **kwargs)
        finally:
            sample["calls"] += 1
            sample["seconds"] += time.monotonic() - started

    def observation(self):
        return {"reader": "chunked-eof-image-v2", "read_chunk_bytes": SCAN_READ_CHUNK,
                "sampled_operations": self.samples, "observed_raw_bytes": self.raw_bytes,
                "exhaustive_cost_model": False}


def scan_plain(path):
    """Fresh lstat at each original ancestor/leaf checkpoint; no stat cache.

    This qualification-only reader also rejects hardlinked files. It is not
    a replacement binding for any frozen collector function or formal action.
    """
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ProposalRefusal("scanner requires an absolute confined path")
    leaf = None
    for item in (*reversed(path.parents), path):
        info = os.lstat(item)
        if (stat.S_ISLNK(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & 0x400
                or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
                or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1)):
            raise ProposalRefusal("scanner linked/reparse/hardlinked/nonregular input")
        if item != path and not stat.S_ISDIR(info.st_mode):
            raise ProposalRefusal("scanner ancestor is not a directory")
        leaf = info
    return leaf


def scan_read(path, maximum, *, totals=None):
    """Preserve walk-time and open-time checks, then check the opened identity.

    Raw EOF bytes set the quota. The post-read check detects observed changes;
    this path-based sample does not establish atomic filesystem custody.
    """
    if type(maximum) is not int or maximum < 0:
        raise ProposalRefusal("nonnegative scanner read quota required")
    totals = ScanTotals() if totals is None else totals
    before = totals.call("path_checks", scan_plain, path)
    if not stat.S_ISREG(before.st_mode):
        raise ProposalRefusal("scanner input is not a regular file")
    def identity(info):
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or not info.st_ino or getattr(info, "st_file_attributes", 0) & 0x400):
            raise ProposalRefusal("scanner opened linked/nonregular/unidentified input")
        return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
    original = identity(before)
    with totals.call("open", Path(path).open, "rb") as stream:
        if identity(totals.call("identity", os.fstat, stream.fileno())) != original:
            raise ProposalRefusal("scanner opened identity differs from fresh leaf")
        pieces, size = [], 0
        while True:
            # The +1 sentinel distinguishes EOF from overflow even at a zero
            # remaining quota. Short reads are not EOF, and observed st_size
            # never selects bytes or shortens the read.
            chunk = totals.call("raw_read", stream.read,
                                min(SCAN_READ_CHUNK, maximum - size + 1))
            totals.raw_bytes += len(chunk)
            if not chunk:
                break
            size += len(chunk)
            if size > maximum:
                raise ProposalRefusal("scanner file exceeds byte quota")
            pieces.append(chunk)
        if identity(totals.call("identity", os.fstat, stream.fileno())) != original:
            raise ProposalRefusal("scanner opened file changed during read")
    if identity(totals.call("identity", os.lstat, path)) != original:
        raise ProposalRefusal("scanner path identity changed during read")
    return b"".join(pieces)


def scan_image(root, *, maximum, path_rule, file_maximum=256 * 1024 * 1024,
               file_count=50_000, physical=True, totals=None):
    """Full fresh qualification image map, with no expected-path projection.

    Frozen initial/final utility measurements independently cross-check normal
    raw identities; they do not prove equivalent rejection/race semantics.
    """
    if (type(maximum) is not int or maximum < 1 or type(file_maximum) is not int
            or file_maximum < 1 or type(file_count) is not int or file_count < 1):
        raise ProposalRefusal("positive scanner bounds required")
    totals = ScanTotals() if totals is None else totals
    root = Path(root)
    if any(part.endswith((".", " ")) or ":" in part for part in root.parts[1:]):
        raise ProposalRefusal("ambiguous scanner root")
    totals.call("path_checks", scan_plain, root)
    root = totals.call("path_checks", root.resolve, strict=True)
    if not stat.S_ISDIR(totals.call("path_checks", scan_plain, root).st_mode):
        raise ProposalRefusal("scanner root is not a directory")
    result, aliases, observed_dirs, total = {}, set(), set(), 0
    def failed(error):
        raise error
    for current, directories, files in os.walk(root, followlinks=False, onerror=failed):
        if not stat.S_ISDIR(totals.call("path_checks", scan_plain, Path(current)).st_mode):
            raise ProposalRefusal("scanner walk directory changed")
        for name in (*directories, *files):
            path = Path(current) / name
            key = path_rule(path.relative_to(root).as_posix())
            if key.casefold() in aliases:
                raise ProposalRefusal("scanner casefold file/directory alias")
            aliases.add(key.casefold())
            info = totals.call("path_checks", scan_plain, path)
            expected_directory = name in directories
            if expected_directory != stat.S_ISDIR(info.st_mode):
                raise ProposalRefusal("scanner enumerated entry changed type")
            if expected_directory:
                observed_dirs.add(key)
        for name in sorted(files):
            path = Path(current) / name
            key = path_rule(path.relative_to(root).as_posix())
            if len(result) >= file_count:
                raise ProposalRefusal("scanner file count exceeds quota")
            raw = scan_read(path, min(file_maximum, maximum - total), totals=totals)
            total += len(raw)
            result[key] = totals.call("hash", sha, raw)
    implied_dirs = {"/".join(name.split("/")[:i]) for name in result
                    for i in range(1, len(name.split("/")))}
    if physical and observed_dirs != implied_dirs:
        raise ProposalRefusal("scanner empty or unbound physical directory")
    return dict(sorted(result.items()))


def reassemble(original_root, record, destination):
    """The original_root must first be fetched/verified by trusted EC control.

    This routine verifies raw parts but does NOT authenticate original_root's
    Git ref, native preparation job, or provenance record by hashing itself.
    """
    chunks = record.get("chunks")
    if type(chunks) is not list or not chunks or len(chunks) > 64:
        raise ProposalRefusal("bounded declared original part order required")
    seen, size, whole = set(), 0, hashlib.sha256()
    destination = plain(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as out:
        for chunk in chunks:  # exact declaration order; never sort part names
            if type(chunk) is not dict or set(chunk) != {"path", "bytes", "sha256"}:
                raise ProposalRefusal("exact part descriptor required")
            name = relative(chunk["path"])
            if name.casefold() in seen or type(chunk["bytes"]) is not int:
                raise ProposalRefusal("duplicate part or non-native byte count")
            seen.add(name.casefold())
            raw = read(original_root / "w3-freeze" / name, MAX_PART)
            if len(raw) != chunk["bytes"] or sha(raw) != chunk["sha256"]:
                raise ProposalRefusal("original part length/hash mismatch")
            size += len(raw)
            if size > MAX_ARCHIVE:
                raise ProposalRefusal("whole archive exceeds bound")
            whole.update(raw)
            out.write(raw)
        out.flush()
        os.fsync(out.fileno())
    if size != record["raw_zip_bytes"] or whole.hexdigest() != record["archive_sha256"]:
        raise ProposalRefusal("ordered whole archive identity mismatch")
    if sha(read(destination, MAX_ARCHIVE)) != record["archive_sha256"]:
        raise ProposalRefusal("reassembled archive readback mismatch")


def restore_image(archive, root, raw_map, bound):
    """Fresh regular files only, all observed members mapped, no pip/npm."""
    mapping = expected_map(raw_map, bound)
    root = plain(root)
    if root.exists():
        raise ProposalRefusal("restoration root must be new")
    root.mkdir(parents=True)
    observed, aliases, total = {}, set(), 0
    with zipfile.ZipFile(archive) as package:
        members = package.infolist()
        if len(members) > 2 * MAX_FILES:
            raise ProposalRefusal("too many archive members")
        for info in members:
            name = relative(info.filename.rstrip("/") if info.is_dir() else info.filename)
            mode = (info.external_attr >> 16) & 0xFFFF
            if (info.flag_bits & 1 or stat.S_IFMT(mode) not in {0, stat.S_IFREG, stat.S_IFDIR}
                    or name.casefold() in aliases):
                raise ProposalRefusal("encrypted/nonregular/duplicate archive member")
            aliases.add(name.casefold())
            if info.is_dir():
                (root / name).mkdir(parents=True, exist_ok=True)
                continue
            if name not in mapping or info.file_size > min(bound, 128 * 1024 * 1024):
                raise ProposalRefusal("undeclared or oversized member")
            total += info.file_size
            if total > bound:
                raise ProposalRefusal("archive expansion quota")
            with package.open(info) as member:
                raw = member.read(info.file_size + 1)
            if len(raw) != info.file_size or sha(raw) != mapping[name]:
                raise ProposalRefusal("restored raw member identity mismatch")
            write_new(root / name, raw)
            observed[name] = sha(raw)
    if observed != mapping or full_map(root, bound) != mapping:
        raise ProposalRefusal("complete restored map mismatch")


def restore_all_original_inputs(original_root, raw_provenance, audit_root, image_roots):
    provenance = json_object(raw_provenance)
    if (provenance.get("repository"), provenance.get("commit"), provenance.get("tree")) != (
            PREP_REPOSITORY, PREP_COMMIT, PREP_TREE):
        raise ProposalRefusal("wrong independently reacquired preparation identity")
    if set(image_roots) != set(IMAGE_BOUNDS):
        raise ProposalRefusal("exact Python/Node/JS image destinations required")
    # Preserve/check all original maps, wheels, archives and image part records,
    # even when an archive is retained only for audit and is never installed.
    maps = {}
    for name, descriptor in provenance["original_maps"].items():
        relative(name)
        raw = read(original_root / relative(descriptor["receipt_path"]), 10_000_000)
        if len(raw) != descriptor["bytes"] or sha(raw) != descriptor["sha256"]:
            raise ProposalRefusal("original map/lock/provenance blob differs")
        write_new(audit_root / "original-maps" / name, raw)
        maps[name] = raw
    records = [(name, provenance["images"][name]) for name in IMAGE_BOUNDS]
    records += list(provenance["original_archives"].items())
    all_parts = set()
    for name, record in records:
        relative(name)
        archive = audit_root / "archives" / (name + ".zip")
        for chunk in record["chunks"]:
            part = relative(chunk["path"])
            if part.casefold() in all_parts:
                raise ProposalRefusal("one raw part reused across image/archive roles")
            all_parts.add(part.casefold())
        reassemble(original_root, record, archive)
        if name in IMAGE_BOUNDS:
            raw_map = maps[name + "-files.json"]
            mapping = expected_map(raw_map, IMAGE_BOUNDS[name])
            if sha(canonical(mapping)) != record["files_sha256"]:
                raise ProposalRefusal("declared complete source-map digest differs")
            restore_image(archive, image_roots[name], raw_map, IMAGE_BOUNDS[name])
    # Requires a prior full original EC inventory check, not a selected-files
    # download: unused .zip.part files must also be rejected as omitted input.
    actual_parts = {p.name.casefold() for p in (original_root / "w3-freeze").glob("*.zip.part")}
    if actual_parts != all_parts:
        raise ProposalRefusal("unused or missing original archive parts")


def verify_original_publication(raw_root):
    """Original byte closure, not an approval/provider construction."""
    manifest = json_object(read(raw_root / "ec-publication.json", 10_000_000))
    context = manifest.get("context")
    if (manifest.get("schema_version") != 1 or manifest.get("status") != "preserved"
            or type(context) is not dict
            or context.get("GITHUB_RUN_ID") != "37207000468"
            or context.get("GITHUB_RUN_ATTEMPT") != "1"
            or context.get("GITHUB_SHA") != "3cce1bc37ae830fce9f64a748f7392659f5b6698"
            or context.get("COMPUTERNAME", "").upper() != HOST
            or context.get("EC_JOB_STATUS") != "success"):
        raise ProposalRefusal("original preparation publication context differs")
    files = manifest.get("files")
    if type(files) is not list or not files or len(files) > 256:
        raise ProposalRefusal("complete bounded preparation inventory required")
    declared, aliases = {}, set()
    for descriptor in files:
        if type(descriptor) is not dict or set(descriptor) != {"path", "bytes", "sha256"}:
            raise ProposalRefusal("exact original publication member required")
        name = relative(descriptor["path"])
        if name == "ec-publication.json" or name.casefold() in aliases:
            raise ProposalRefusal("original inventory role/alias violation")
        aliases.add(name.casefold())
        raw = read(raw_root / name, 10_000_000)
        if type(descriptor["bytes"]) is not int or len(raw) != descriptor["bytes"] or sha(raw) != descriptor["sha256"]:
            raise ProposalRefusal("original publication raw member differs")
        declared[name] = sha(raw)
    declared["ec-publication.json"] = sha(read(raw_root / "ec-publication.json", 10_000_000))
    if full_map(raw_root, 200_000_000) != declared:
        raise ProposalRefusal("original receipt inventory drops/adds raw files")
    return manifest


def qualification_source_closure(source):
    raw_manifest = read(source / "campaigns/checkwash-wave-3/manifest.json", 10_000_000)
    if sha(raw_manifest) != MANIFEST_SHA256:
        raise ProposalRefusal("exact Phase1 manifest raw hash differs")
    manifest = json_object(raw_manifest)
    observed = {}
    for name, descriptor in manifest["assets"].items():
        relative(name)
        if type(descriptor) is not dict or set(descriptor) != {"sha256", "git_blob"}:
            raise ProposalRefusal("exact frozen asset descriptor required")
        raw = read(source / name, 10_000_000)
        blob = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
        if sha(raw) != descriptor["sha256"] or blob != descriptor["git_blob"]:
            raise ProposalRefusal("qualification source frozen raw/Git blob closure differs")
        observed[name] = sha(raw)
    roots = manifest["closed_roots"]
    if type(roots) is not list or not roots:
        raise ProposalRefusal("frozen closed-root roster missing")
    # The whole inserted import root is closed, including siblings of the
    # smallestlie package. An unlisted src/yaml.py must not enter the loader.
    for root_name in [*roots, "src"]:
        relative(root_name)
        actual = full_map(source / root_name, 200_000_000)
        expected = {name[len(root_name) + 1:]: descriptor["sha256"]
                    for name, descriptor in manifest["assets"].items() if name.startswith(root_name + "/")}
        if actual != expected:
            raise ProposalRefusal("actual closed root/import surface has extra or missing files")
    return manifest, observed


def load_qualification_collector(source):
    """Load frozen definitions to qualify utilities; creates no PreparedRun."""
    source = plain(source).resolve()
    manifest, _ = qualification_source_closure(source)
    entry = source / COLLECTOR_PATH
    if sha(read(entry, 10_000_000)) != COLLECTOR_SHA256:
        raise ProposalRefusal("qualification collector raw pin differs")
    sys.path.insert(0, str(source / "src"))
    spec = importlib.util.spec_from_file_location("w3_qualification_collector", entry)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module, manifest


def private_qualification(source, work, out, generation):
    """Actual native bootstrap experiments; no W3 fixture/engine/lifecycle."""
    if os.name != "nt" or os.environ.get("COMPUTERNAME", "").upper() != HOST:
        raise ProposalRefusal("qualification host mismatch")
    progress = PrivateProgress(out)
    progress.emit("private-loader-entered")
    private = plain(work / "images/python").resolve()
    if (not sys.flags.isolated or not sys.flags.no_user_site or not sys.dont_write_bytecode
            or Path(sys.prefix).resolve() != private or Path(sys.base_prefix).resolve() != private
            or Path(sys.executable).resolve() != private / "python.exe"):
        raise ProposalRefusal("sealed private -I -B loader did not activate")
    progress.emit("collector-load-started")
    collector, manifest = load_qualification_collector(source)
    progress.emit("collector-load-completed")
    installation = source / "campaigns/checkwash-wave-3/installations"
    python_map = expected_map(read(installation / "python-files.json", 10_000_000), IMAGE_BOUNDS["python"])
    node_map = expected_map(read(installation / "node-files.json", 10_000_000), IMAGE_BOUNDS["node"])
    js_map = expected_map(read(installation / "js-files.json", 10_000_000), IMAGE_BOUNDS["js"])
    if progress.measure("initial-python-map", lambda: collector.measure_tree(
            private, IMAGE_BOUNDS["python"])) != python_map:
        raise ProposalRefusal("private prefix raw identity differs")
    node_root, js_root = work / "images/node", work / "images/js"
    if progress.measure("initial-node-map", lambda: collector._image_tree(
            node_root, maximum=IMAGE_BOUNDS["node"])) != node_map:
        raise ProposalRefusal("actual collector Node map rejects/differs from original")
    if progress.measure("initial-js-map", lambda: collector._image_tree(
            js_root, maximum=IMAGE_BOUNDS["js"])) != js_map:
        raise ProposalRefusal("actual collector JS map rejects/differs from original")
    literal = json_object(read(source / "campaigns/checkwash-wave-3/contracts/verifier-environment.json", 10_000_000))
    if canonical(literal) != canonical({"semantic_env": collector.VERIFIER_ENV}):
        raise ProposalRefusal("exact frozen verifier environment differs")
    from smallestlie.sandbox.windows_capture import capture_windows
    generation = plain(generation).resolve()
    generation_info = json_object(read(generation / "generation.json", 10_000_000))
    write_new(out / "generation.json", read(generation / "generation.json", 10_000_000))
    mingit = generation / "mingit/cmd/git.exe"
    # EC component_paths uses <generation>/<component>/<declared executable>.
    # Verify native generation metadata; no new executable hash is fabricated.
    if generation_info.get("name") != generation.name or generation_info["components"]["mingit"]["sha256"] != (
            "56d7b226b7693196cfc71fef26568f536c4a021ab6c37ff2db4287bed908e96e"):
        raise ProposalRefusal("actual pinned generation MinGit archive differs")
    if not mingit.is_file():
        raise ProposalRefusal("generation MinGit two-level layout missing")
    git_root = mingit.parent.parent
    git_map = progress.measure("initial-mingit-map", lambda: collector._image_tree(
        git_root, maximum=256 * 1024 * 1024))
    progress.emit("qualification-image-scanner-selected", reader="chunked-eof-image-v2")
    def protected_maps():
        py = progress.measure_scan("protected-python-map", lambda totals: scan_image(
            private, maximum=IMAGE_BOUNDS["python"], path_rule=collector._artifact_path,
            file_maximum=10_000_000, file_count=20_000, physical=False, totals=totals))
        node = progress.measure_scan("protected-node-map", lambda totals: scan_image(
            node_root, maximum=IMAGE_BOUNDS["node"], path_rule=collector._installation_path,
            totals=totals))
        js = progress.measure_scan("protected-js-map", lambda totals: scan_image(
            js_root, maximum=IMAGE_BOUNDS["js"], path_rule=collector._installation_path,
            totals=totals))
        git = progress.measure_scan("protected-mingit-map", lambda totals: scan_image(
            git_root, maximum=256 * 1024 * 1024, path_rule=collector._installation_path,
            totals=totals))
        sources = progress.measure("protected-frozen-source-map", lambda:
            qualification_source_closure(source)[1])
        if py != python_map or node != node_map or js != js_map or git != git_map:
            raise ProposalRefusal("actual protected image drift during qualification")
        return {"python": py, "node": node, "js": js, "mingit": git, "frozen_sources": sources}
    before_maps = protected_maps()
    write_new(out / "protected-before.json", canonical(before_maps))
    probe = work / "native-probe"
    probe.mkdir()
    system = plain(Path(os.environ["SYSTEMROOT"])).resolve()
    env = {key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP", "COMPUTERNAME")
           if key in os.environ}
    env.update(collector.VERIFIER_ENV)
    env["PATH"] = str(mingit.parent) + os.pathsep + str(system / "System32")
    captures = []
    def capture(label, argv, cwd=probe):
        if len(captures) >= 24:
            raise ProposalRefusal("qualification native child budget exceeded")
        progress.emit("capture-started", label=label)
        progress.emit("capture-premap-started", label=label)
        before = protected_maps()
        progress.emit("capture-premap-completed", label=label)
        progress.emit("capture-child-started", label=label)
        result = capture_windows(tuple(map(str, argv)), cwd, env=env, timeout_seconds=30,
                                 max_output_bytes=1_000_000, cleanup_seconds=5)
        write_new(out / "native" / (label + ".stdout.raw"), result.stdout)
        write_new(out / "native" / (label + ".stderr.raw"), result.stderr)
        write_new(out / "native" / (label + ".capture.json"), canonical(result.metadata()))
        progress.emit("capture-child-returned", label=label,
                      exit_code=result.exit_code, termination_kind=result.termination_kind)
        progress.emit("capture-postmap-started", label=label)
        after = protected_maps()
        metadata = {**result.metadata(), "protected_before_sha256": sha(canonical(before)),
                    "protected_after_sha256": sha(canonical(after))}
        write_new(out / "native" / (label + ".metadata.json"), canonical(metadata))
        progress.emit("capture-postmap-completed", label=label)
        captures.append(label)
        if (result.termination_kind != "completed" or result.exit_code != 0
                or not result.output_complete or not result.descendants_reaped):
            raise ProposalRefusal("actual native qualification child did not complete")
        progress.emit("capture-completed", label=label)
        return result.stdout
    binary = capture("private-binary", [sys.executable, "-I", "-B", "-c",
        "import os;os.write(1,bytes([0,255,13,10]));os.write(2,b'raw-stderr\\r\\n')"])
    if binary != bytes([0, 255, 13, 10]):
        raise ProposalRefusal("raw Windows stdout pipe bytes changed")
    if read(out / "native/private-binary.stderr.raw", 1_000_000) != b"raw-stderr\r\n":
        raise ProposalRefusal("raw Windows stderr pipe bytes changed")
    version = capture("node-version", [node_root / "node.exe", "--version"])
    if version != read(installation / "node-version.stdout", 1_000_000):
        raise ProposalRefusal("actual sealed Node version native bytes differ")
    opts = ["-c", "core.hooksPath=NUL", "-c", "core.autocrlf=false", "-c", "core.eol=lf",
            "-c", "core.attributesFile=NUL", "-c", "commit.gpgSign=false", "-c", "core.fsmonitor=false"]
    def git(label, *args):
        return capture(label, [mingit, *opts, *args])
    if not re.fullmatch(rb"git version 2\.55\.0(?:\.windows\.\d+)?\r?\n", git("git-version", "--version")):
        raise ProposalRefusal("actual generation MinGit native version differs")
    template = work / "empty-qualification-template"
    template.mkdir()
    git("git-init", "init", "--object-format=sha1", "--initial-branch=main", "--template=" + str(template))
    # This benign file is not a W3 fixture or production/test variant.
    file = probe / "bootstrap.txt"
    first, second = b"native baseline\r\n", b"native attack\r\n"
    write_new(file, first)
    git("git-add-base", "add", "--all", "--", ".")
    git("git-commit-base", "commit", "-m", "bootstrap baseline")
    base = git("git-base-oid", "rev-parse", "HEAD").decode("ascii").strip()
    file.unlink()
    write_new(file, second)
    git("git-add-head", "add", "--all", "--", ".")
    git("git-commit-head", "commit", "-m", "bootstrap head")
    head = git("git-head-oid", "rev-parse", "HEAD").decode("ascii").strip()
    if not all(re.fullmatch(r"[0-9a-f]{40}", value) for value in (base, head)) or base == head:
        raise ProposalRefusal("actual qualification commits missing/distinctness failure")
    if git("git-parent", "rev-parse", "HEAD~1").decode("ascii").strip() != base:
        raise ProposalRefusal("actual benign qualification range differs")
    for label, revision, raw in (("base", base, first), ("head", head, second)):
        tree = git("git-tree-" + label, "ls-tree", "-r", "-z", "--full-tree", revision)
        records = tree.split(b"\0")
        if len(records) != 2 or records[-1] != b"":
            raise ProposalRefusal("benign Git full tree omitted/added inputs")
        header, name = records[0].split(b"\t", 1)
        mode, kind, oid = header.decode("ascii").split(" ")
        if mode != "100644" or kind != "blob" or name != b"bootstrap.txt":
            raise ProposalRefusal("benign native Git full tree invalid")
        if git("git-blob-" + label, "cat-file", "blob", oid) != raw:
            raise ProposalRefusal("native Git raw blob bytes differ")
    if collector._image_tree(probe, maximum=10_000_000, git_admin=True) != {"bootstrap.txt": sha(second)}:
        raise ProposalRefusal("benign actual worktree full map differs")
    # Full installation/source closure after native children; no post-filtering.
    if (progress.measure("final-python-map", lambda: collector.measure_tree(
            private, IMAGE_BOUNDS["python"])) != python_map
            or progress.measure("final-node-map", lambda: collector._image_tree(
                node_root, maximum=IMAGE_BOUNDS["node"])) != node_map
            or progress.measure("final-js-map", lambda: collector._image_tree(
                js_root, maximum=IMAGE_BOUNDS["js"])) != js_map
            or progress.measure("final-mingit-map", lambda: collector._image_tree(
                git_root, maximum=256 * 1024 * 1024)) != git_map):
        raise ProposalRefusal("sealed Python/Node/JS/MinGit installation changed during qualification")
    after_maps = protected_maps()
    write_new(out / "protected-after.json", canonical(after_maps))
    write_new(out / "qualification.json", canonical({
        "document_kind": "bootstrap-native-qualification-observations",
        "scope": "restoration/private-loader/raw-capture/Node-version/benign-MinGit-range only",
        "host": HOST, "generation": generation.name,
        "collector_sha256": COLLECTOR_SHA256, "native_capture_labels": captures,
        "protected_image_reader": "qualification-only/chunked-eof-image-v2",
        "python_prefix_sha256": sha(canonical(python_map)), "node_tree_sha256": sha(canonical(node_map)),
        "js_tree_sha256": sha(canonical(js_map)), "mingit_tree_sha256": sha(canonical(git_map)),
        "mingit_executable_sha256": sha(read(mingit, 256 * 1024 * 1024)),
        "base_commit": base, "head_commit": head,
        "formal_execution": False, "collector_adoption": False,
        "host_storage_adoption": False, "OS_network_adoption": False}))
    progress.emit("private-qualification-completed")
    return 0


def _bootstrap_qualification_entry():
    """Suggested new entry workloads/m12_w3_bootstrap_qualify/run.py.

    Requires a separately reviewed EC prefetch step setting the fixed
    EC_W3_PREPARATION_INPUT folder. That step owns all credentials and fetches
    complete original prep receipt into raw/, raw native API/Git evidence into
    proof/. No formal-action source/ACK broker or persistent campaign storage.
    """
    if os.name != "nt" or os.environ.get("COMPUTERNAME", "").upper() != HOST:
        raise ProposalRefusal("bootstrap qualification host mismatch")
    if os.environ.get("EC_WORKLOAD_NAME") != "m12-w3-bootstrap-qualify":
        raise ProposalRefusal("dedicated new declaration required")
    if any(os.environ.get(key) for key in ("RECEIPT_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "EC_WORKLOAD_APP_KEY")):
        raise ProposalRefusal("qualification payload received credentials")
    source = plain(Path(os.environ["EC_WORKLOAD_SOURCE"])).resolve()
    work = plain(Path(os.environ["EC_WORKLOAD_WORK"])).resolve() / "w3-bootstrap"
    out = plain(Path(os.environ["EC_WORKLOAD_OUT"])).resolve() / "w3-bootstrap"
    expected_input = plain(Path(os.environ["EC_WORKLOAD_WORK"])).resolve() / "preparation-inputs"
    inputs = plain(Path(os.environ.get("EC_W3_PREPARATION_INPUT", str(expected_input)))).resolve()
    if inputs != expected_input:
        raise ProposalRefusal("fixed trusted EC prefetch input location required")
    # Raw authority evidence is retained for independent acceptance. Its flags
    # are not inspected as proofs, and no formal authority object is created.
    for path in inputs.rglob("*"):
        plain(path)
        if path.is_file():
            rel = relative(path.relative_to(inputs).as_posix())
            if not rel.startswith(("raw/", "proof/")) and rel != "preflight-input.json":
                raise ProposalRefusal("unexpected prefetch contract path")
    provenance_raw = read(source / "campaigns/checkwash-wave-3/installations/provenance.json", 10_000_000)
    work.mkdir(parents=True, exist_ok=False)
    out.mkdir(parents=True, exist_ok=False)
    private_tmp = work / "tmp"
    private_tmp.mkdir()
    child_env = dict(os.environ)
    child_env["TEMP"], child_env["TMP"] = str(private_tmp), str(private_tmp)
    def stage(name):
        write_new(out / "progress" / (name + ".json"), canonical({"stage": name, "formal_execution": False}))
    stage("01-guards-started")
    # This helper belongs to the new accepted workload source, outside the
    # previously frozen src/contracts/fixtures. Its failures stop qualification.
    guards = Path(__file__).with_name("guard_checks.py")
    read(guards, 1_000_000)
    with (out / "guards.stdout.raw").open("xb") as stdout, (out / "guards.stderr.raw").open("xb") as stderr:
        guard_result = subprocess.run([sys.executable, "-I", "-B", str(guards), str(Path(__file__).resolve())],
            cwd=work, env=child_env, stdout=stdout, stderr=stderr, timeout=60, check=False)
        stdout.flush(); os.fsync(stdout.fileno())
        stderr.flush(); os.fsync(stderr.fileno())
    read(out / "guards.stdout.raw", 1_000_000)
    read(out / "guards.stderr.raw", 1_000_000)
    write_new(out / "guards-result.json", canonical({"document_kind": "restoration-guard-check-observations",
        "argv": [sys.executable, "-I", "-B", str(guards), str(Path(__file__).resolve())],
        "exit_code": guard_result.returncode, "formal_execution": False}))
    if guard_result.returncode != 0:
        raise ProposalRefusal("restoration guard checks failed; original streams retained")
    stage("02-original-publication-readback")
    image_roots = {name: work / "images" / name for name in IMAGE_BOUNDS}
    verify_original_publication(inputs / "raw")
    stage("03-restore-original-inputs-started")
    restore_all_original_inputs(inputs / "raw", provenance_raw, work / "audit", image_roots)
    stage("04-restored-images-readback")
    # Keep bounded small authority records/maps; original large parts remain at
    # the already immutable prep ref. Do not republish hundreds of MB in action.
    # EC already preserves original proof at out/w3-preparation-prefetch. Bind
    # the complete input raw/proof inventory instead of republishing it twice.
    proof_map = full_map(inputs / "proof", 10_000_000)
    preflight_raw = read(inputs / "preflight-input.json", 10_000_000)
    write_new(out / "prefetch-input-identity.json", canonical({
        "preflight_input_sha256": sha(preflight_raw), "proof_map": proof_map,
        "raw_map": full_map(inputs / "raw", 200_000_000), "formal_execution": False}))
    stage("05-private-loader-started")
    generation = plain(Path(os.environ["EC_POOL_GENERATION"])).resolve()
    private = image_roots["python"] / "python.exe"
    command = [str(private), "-I", "-B", str(Path(__file__).resolve()), "--private-qualify",
               str(source), str(work), str(out), str(generation)]
    started = time.monotonic()
    code, note = None, None
    termination_kind, streams = "unavailable", {}
    try:
        with (out / "private-loader.stdout.raw").open("xb") as stdout, (out / "private-loader.stderr.raw").open("xb") as stderr:
            try:
                result = subprocess.run(command, cwd=work, env=child_env, stdout=stdout, stderr=stderr,
                                        timeout=1200, check=False)
                code, termination_kind = result.returncode, "completed"
            except subprocess.TimeoutExpired:
                termination_kind = "timeout"
                note = "private qualification exceeded bounded 1200-second loader interval"
            finally:
                stdout.flush(); os.fsync(stdout.fileno())
                stderr.flush(); os.fsync(stderr.fileno())
        for path in (out / "private-loader.stdout.raw", out / "private-loader.stderr.raw"):
            raw = read(path, 1_000_000)
            streams[path.name] = {"bytes": len(raw), "sha256": sha(raw)}
        if code == 0:
            read(out / "qualification.json", 1_000_000)
    finally:
        write_new(out / "bootstrap-result.json", canonical({"document_kind": "bootstrap-entry-observation",
            "argv": command, "exit_code": code, "note": note,
            "termination_kind": termination_kind, "stream_readback": streams,
            "seconds": time.monotonic() - started, "formal_execution": False,
            "collector_adoption": False, "host_storage_adoption": False}))
    return code if type(code) is int and code != 0 else (0 if code == 0 else 1)


def bootstrap_qualification_entry():
    try:
        return _bootstrap_qualification_entry()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        target = Path(os.environ.get("EC_WORKLOAD_OUT", ".")) / "w3-bootstrap"
        if target.is_dir():
            partial = {}
            work = Path(os.environ.get("EC_WORKLOAD_WORK", ".")) / "w3-bootstrap"
            for name, bound in IMAGE_BOUNDS.items():
                root = work / "images" / name
                if root.is_dir():
                    try:
                        partial[name] = {"observed_partial_map": full_map(root, bound)}
                    except (OSError, ValueError) as diagnostic:
                        partial[name] = {"measurement_unavailable": type(diagnostic).__name__}
            write_new(target / "bootstrap-failure.json", canonical({
                "document_kind": "bootstrap-failure-observations", "exception_type": type(error).__name__,
                "diagnostic": str(error), "partial_images": partial,
                "progress": full_map(target / "progress", 1_000_000) if (target / "progress").is_dir() else {},
                "formal_execution": False, "collector_adoption": False}))
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-qualify", nargs=4, metavar=("SOURCE", "WORK", "OUT", "GENERATION"))
    args = parser.parse_args()
    try:
        if args.private_qualify is not None:
            raise SystemExit(private_qualification(*(Path(item) for item in args.private_qualify)))
        raise SystemExit(bootstrap_qualification_entry())
    except (OSError, ValueError, KeyError) as error:
        if args.private_qualify is not None:
            private_out = Path(args.private_qualify[2])
            if private_out.is_dir():
                write_new(private_out / "private-qualification-failure.json", canonical({
                    "document_kind": "private-bootstrap-failure-observations",
                    "exception_type": type(error).__name__, "diagnostic": str(error),
                    "formal_execution": False, "collector_adoption": False}))
        print("W3 bootstrap qualification refused: " + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
