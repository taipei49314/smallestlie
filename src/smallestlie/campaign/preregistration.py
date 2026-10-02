"""Freeze designs for one formal run; approval is supplied independently.

This module reads Git objects and files, never executes fixtures or runners.
Git dates are not proof of run order. A configured authority must authenticate
the Phase-1 approval and the later request outside the declaration itself.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any, Protocol

from smallestlie.adapters.checkwash import PINNED_SHA256, PINNED_SOURCE_REVISION, PINNED_VERSION
from smallestlie.adjudication.residuals import PINNED_INDEX_SHA256
from smallestlie.attacks.adjudication import choice, mapping, relative_path, sha256, string, strings
from smallestlie.attacks.schema import AttackSchemaError, V2, load_mapping_bytes, parse_attack_spec
from smallestlie.verdict.json_input import read_json

PROTOCOL = "smallestlie.m12/v1"
ARMS = {"baseline", "attack", "twin", "repair"}


class PreregistrationError(ValueError):
    pass


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_digest(value: Any) -> str:
    return digest(json.dumps(value, sort_keys=True, ensure_ascii=True,
                             separators=(",", ":"), allow_nan=False).encode("ascii"))


def commit(value: Any, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
        raise PreregistrationError(f"{label} requires an exact Git SHA-1")
    return value


def integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise PreregistrationError(f"{label} requires an integer >= {minimum}")
    return value


def json_mapping(data: bytes, label: str) -> dict:
    if type(data) is not bytes or len(data) > 10_000_000:
        raise PreregistrationError(f"{label} must be bytes within the size limit")
    try:
        value = read_json(data.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise PreregistrationError(f"invalid {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise PreregistrationError(f"{label} must be a JSON object")
    return value


def _plain(path: Path) -> None:
    attrs = path.lstat()
    if (stat.S_ISLNK(attrs.st_mode) or getattr(attrs, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)):
        raise PreregistrationError(f"linked/reparse input: {path}")


def _file(root: Path, ref: str) -> bytes:
    relative_path(ref, "asset path")
    path = root
    for component in ref.split("/"):
        if component == ".git":
            raise PreregistrationError("Git metadata cannot be an input asset")
        path = path / component
        _plain(path)
    if not path.is_file():
        raise PreregistrationError(f"asset is not a regular file: {ref}")
    return path.read_bytes()


def _files_under(root: Path, ref: str) -> tuple[set[str], set[str]]:
    relative_path(ref, "closed root")
    directory = root
    for component in ref.split("/"):
        if component == ".git":
            raise PreregistrationError("Git metadata cannot be a closed root")
        directory /= component
        _plain(directory)
    if not directory.is_dir():
        raise PreregistrationError(f"closed root is not a directory: {ref}")
    result, directories = set(), set()
    def unreadable(error: OSError) -> None:
        raise error
    for parent, dirs, files in os.walk(directory, followlinks=False, onerror=unreadable):
        directories.add(Path(parent).relative_to(root).as_posix())
        for name in [*dirs, *files]:
            _plain(Path(parent) / name)
        for name in files:
            path = Path(parent) / name
            if not path.is_file():
                raise PreregistrationError("non-regular frozen input")
            result.add(path.relative_to(root).as_posix())
    return result, directories


def _git(root: Path, *args: str) -> bytes:
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True,
                            timeout=30, check=False)
    if result.returncode:
        raise PreregistrationError(f"Git proof failed: {args[0]}")
    return result.stdout


@dataclass(frozen=True)
class RunRequest:
    campaign_id: str
    request_id: str
    run_id: str
    phase1_commit: str
    source_commit: str
    manifest_sha256: str
    authorization_ref: str

    def payload(self) -> dict:
        return dict(self.__dict__)


@dataclass(frozen=True)
class PreregistrationApproval:
    provider_id: str
    reference: str
    phase1_commit: str
    manifest_sha256: str
    request_sha256: str


class PreregistrationAuthority(Protocol):
    def verify(self, request: RunRequest) -> PreregistrationApproval | None:
        """Read an independent human-merge/dispatch source, not manifest claims."""
        ...


@dataclass(frozen=True)
class PreparedRun:
    request: RunRequest
    manifest_bytes: bytes
    lock_bytes: bytes
    profiles: tuple[tuple[str, bytes], ...]
    assets: tuple[tuple[str, bytes], ...]

    def asset(self, path: str) -> bytes:
        for ref, data in self.assets:
            if ref == path:
                return data
        raise PreregistrationError(f"unfrozen asset: {path}")

    def lock(self) -> dict:
        return json_mapping(self.lock_bytes, "prepared lock")

    def profile(self, case_id: str) -> dict:
        for key, data in self.profiles:
            if key == case_id:
                return json_mapping(data, "runner profile")
        raise PreregistrationError(f"undeclared case: {case_id}")

    def binding(self, case_id: str) -> dict:
        for case in self.lock()["cases"]:
            if case["case_id"] == case_id:
                return case
        raise PreregistrationError(f"undeclared case: {case_id}")


def validate_profile(data: bytes) -> dict:
    raw = json_mapping(data, "runner profile")
    mapping(raw, "profile", {"schema_version", "profile_id", "baseline_assertion", "runner",
            "runtime", "dependencies", "collector_sha256", "semantic_env", "arms", "report_format",
            "assertion_exit_codes", "assertion_failure", "collector_path"})
    choice(raw["schema_version"], "profile.schema_version", {"smallestlie.runner-profile/v1"})
    for key in ("profile_id", "baseline_assertion"):
        string(raw[key], key)
    choice(raw["report_format"], "report_format", {"junit", "mocha-json", "vitest-junit"})
    if not isinstance(raw["assertion_exit_codes"], list) or not raw["assertion_exit_codes"]:
        raise PreregistrationError("assertion exit codes are required")
    codes = [integer(code, "assertion exit code", minimum=1) for code in raw["assertion_exit_codes"]]
    if len(set(codes)) != len(codes):
        raise PreregistrationError("duplicate assertion exit code")
    if codes != [1]:
        raise PreregistrationError("M12 supports only assertion exit 1; other runner exits remain unknown")
    for key in ("runner", "runtime"):
        item = mapping(raw[key], key, {"name", "version", "artifact_sha256"})
        string(item["name"], key)
        string(item["version"], key)
        sha256(item["artifact_sha256"], key)
    if (raw["runner"]["name"], raw["report_format"]) not in {
            ("pytest", "junit"), ("mocha", "mocha-json"), ("vitest", "vitest-junit")}:
        raise PreregistrationError("unsupported runner/report contract")
    if raw["report_format"] == "vitest-junit" and raw["runner"]["version"] != "3.2.7":
        raise PreregistrationError("Vitest external JUnit contract supports only 3.2.7")
    predicate = raw["assertion_failure"]
    if raw["report_format"] in {"junit", "vitest-junit"}:
        mapping(predicate, "assertion failure", {"message_contains", "text_contains"})
        string(predicate["message_contains"], "assertion message predicate")
        string(predicate["text_contains"], "assertion trace predicate")
    else:
        mapping(predicate, "Mocha assertion failure", {"message_contains"})
        string(predicate["message_contains"], "Mocha assertion message predicate")
    deps = mapping(raw["dependencies"], "dependencies", {"lock_path", "installed_sha256"})
    relative_path(deps["lock_path"], "dependency lock")
    sha256(deps["installed_sha256"], "installed dependencies")
    sha256(raw["collector_sha256"], "collector")
    relative_path(raw["collector_path"], "collector path")
    if not isinstance(raw["semantic_env"], dict):
        raise PreregistrationError("semantic_env requires a mapping of effective values")
    for key, value in raw["semantic_env"].items():
        string(key, "environment key")
        if not isinstance(value, str):
            raise PreregistrationError("environment values must be strings")
    commands = mapping(raw["arms"], "profile.arms", ARMS)
    for arm in commands.values():
        mapping(arm, "arm command", {"argv", "cwd", "config_paths"})
        if not isinstance(arm["argv"], list) or not arm["argv"]:
            raise PreregistrationError("argv must be a nonempty array")
        for arg in arm["argv"]:
            string(arg, "argv argument")
        if arm["cwd"] != ".":
            relative_path(arm["cwd"], "logical cwd")
        for path in strings(arm["config_paths"], "config paths", allow_empty=True):
            relative_path(path, "config path")
    if commands["baseline"] != commands["repair"]:
        raise PreregistrationError("repair must run the baseline command/configuration")
    return raw


def derive_variant(base: dict[str, bytes], mutations: list[dict]) -> dict[str, bytes]:
    """The narrow M12 UTF-8 byte mutation contract; no file writes/subprocesses.

    Structured/directory operations remain unsupported rather than trusting a
    separate variant declaration. Slice D must materialize these exact bytes.
    """
    result = dict(base)
    for mutation in mutations:
        operation = mutation.get("type")
        required = {"type", "path"} | ({"old", "new"} if operation == "replace_text" else {"content"})
        if operation not in {"replace_text", "write_text", "write_json"}:
            raise PreregistrationError(f"unsupported frozen mutation derivation: {operation}")
        mapping(mutation, "frozen mutation", required, {"expected_count"} if operation == "replace_text" else set())
        path = relative_path(mutation["path"], "mutation path")
        if operation == "replace_text":
            old = string(mutation["old"], "old text")
            new = mutation["new"]
            if not isinstance(new, str) or path not in result:
                raise PreregistrationError("replace_text requires a file and string replacement")
            text = result[path].decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
            count = text.count(old)
            if count < 1 or ("expected_count" in mutation and count != integer(mutation["expected_count"], "expected count", minimum=1)):
                raise PreregistrationError("replace_text match count differs from frozen design")
            result[path] = text.replace(old, new).encode("utf-8")
        elif operation == "write_text":
            if not isinstance(mutation["content"], str):
                raise PreregistrationError("write_text requires string content")
            result[path] = mutation["content"].encode("utf-8")
        else:
            result[path] = (json.dumps(mutation["content"], indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
    return result


def prepare_run(root: str | Path, manifest_path: str, request: RunRequest,
                *, authority: PreregistrationAuthority | None) -> PreparedRun:
    """Authenticate a closed design before Slice D may create any workspace.

    No fallback approval or implicit trust provider exists. Files are read once;
    every parse consumes those captured bytes. Returned state owns immutable bytes.
    """
    try:
        for key in ("campaign_id", "request_id", "run_id", "authorization_ref"):
            string(getattr(request, key), key)
        commit(request.phase1_commit, "phase1_commit")
        commit(request.source_commit, "source_commit")
        sha256(request.manifest_sha256, "manifest_sha256")
        if authority is None:
            raise PreregistrationError("preregistration_authority_missing")
        approval = authority.verify(request)
        if (not isinstance(approval, PreregistrationApproval)
                or approval.phase1_commit != request.phase1_commit
                or approval.manifest_sha256 != request.manifest_sha256
                or approval.request_sha256 != canonical_digest(request.payload())
                or approval.reference != request.authorization_ref):
            raise PreregistrationError("preregistration_approval_mismatch")
        string(approval.provider_id, "approval provider")
        project = Path(root).absolute()
        _plain(project)
        if _git(project, "rev-parse", "HEAD").decode("ascii").strip() != request.source_commit:
            raise PreregistrationError("execution source is not the requested HEAD")
        if _git(project, "status", "--porcelain", "-z"):
            raise PreregistrationError("execution source must be clean")
        _git(project, "merge-base", "--is-ancestor", request.phase1_commit, request.source_commit)
        manifest_bytes = _file(project, manifest_path)
        if digest(manifest_bytes) != request.manifest_sha256:
            raise PreregistrationError("manifest digest mismatch")
        if _git(project, "show", f"{request.phase1_commit}:{manifest_path}") != manifest_bytes:
            raise PreregistrationError("manifest did not exist unchanged at Phase 1")
        manifest = json_mapping(manifest_bytes, "manifest")
        mapping(manifest, "manifest", {"schema_version", "campaign_id", "catalog_path", "assets",
                "closed_roots", "cases", "engine_path", "residual_index_path", "contract_paths"})
        choice(manifest["schema_version"], "manifest schema", {"smallestlie.preregistration/v1"})
        if manifest["campaign_id"] != request.campaign_id:
            raise PreregistrationError("campaign mismatch")
        if not isinstance(manifest["assets"], dict) or not manifest["assets"]:
            raise PreregistrationError("assets must enumerate frozen files")
        files = {}
        phase1_tree = {}
        for record in _git(project, "ls-tree", "-r", "-z", request.phase1_commit).split(b"\0"):
            if record:
                metadata, path_bytes = record.split(b"\t", 1)
                phase1_tree[path_bytes.decode("utf-8")] = metadata.decode("ascii")
        for path, record in manifest["assets"].items():
            relative_path(path, "asset")
            if path == manifest_path:
                raise PreregistrationError("manifest must not hash itself")
            mapping(record, "asset", {"sha256", "git_blob"})
            sha256(record["sha256"], "asset digest")
            commit(record["git_blob"], "asset blob")
            data = _file(project, path)
            blob = hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()
            if (digest(data) != record["sha256"] or blob != record["git_blob"]
                    or phase1_tree.get(path) not in (f"100644 blob {blob}", f"100755 blob {blob}")):
                raise PreregistrationError(f"frozen asset differs from Phase 1: {path}")
            files[path] = data
        closed_roots = strings(manifest["closed_roots"], "closed roots")
        if "src/smallestlie" not in closed_roots:
            raise PreregistrationError("the complete harness package must be a frozen closed root")
        for ref in closed_roots:
            observed, observed_directories = _files_under(project, ref)
            expected = {path for path in files if path.startswith(ref + "/")}
            expected_directories = {"/".join(path.split("/")[:index]) for path in expected
                                    for index in range(len(ref.split("/")), len(path.split("/")))}
            if observed != expected or observed_directories != expected_directories or not expected:
                raise PreregistrationError(f"incomplete frozen file closure: {ref}")
        def asset(ref: str) -> bytes:
            relative_path(ref, "asset reference")
            if ref not in files:
                raise PreregistrationError(f"unfrozen reference: {ref}")
            return files[ref]
        contract_refs = strings(manifest["contract_paths"], "contract paths")
        package_refs = {path for path in files if path.startswith("src/smallestlie/")}
        if not package_refs or not package_refs.issubset(contract_refs):
            raise PreregistrationError("contract paths must include the complete frozen harness package")
        for ref in contract_refs:
            asset(ref)
            if not any(ref.startswith(closed + "/") for closed in closed_roots):
                raise PreregistrationError("execution contracts need a closed root")
        asset("pyproject.toml")
        asset("uv.lock")
        engine_bytes = asset(manifest["engine_path"])
        index_bytes = asset(manifest["residual_index_path"])
        if digest(engine_bytes) != PINNED_SHA256 or digest(index_bytes) != PINNED_INDEX_SHA256:
            raise PreregistrationError("engine/residual index differs from published pin")
        index = json_mapping(index_bytes, "residual index")
        for source in index["sources"]:
            if digest(asset(source["path"])) != source["sha256"]:
                raise PreregistrationError("residual source mismatch")
        catalog_bytes = asset(manifest["catalog_path"])
        catalog = load_mapping_bytes(catalog_bytes, source_path=manifest["catalog_path"])
        mapping(catalog, "catalog", {"schema_version", "name", "attacks", "engine", "residual_index"},
                {"mode", "seed_default"})
        choice(catalog["schema_version"], "catalog schema", {"smallestlie.catalog/v2"})
        ids = strings(catalog["attacks"], "catalog attacks")
        string(catalog["name"], "catalog name")
        if type(catalog.get("seed_default", 49314)) is not int:
            raise PreregistrationError("catalog seed requires an integer")
        if catalog.get("mode", "single") != "single" or catalog["residual_index"] != manifest["residual_index_path"]:
            raise PreregistrationError("only the complete single v2 catalog can be frozen")
        expected_engine = {"version": PINNED_VERSION, "artifact_sha256": PINNED_SHA256,
                           "source_revision": PINNED_SOURCE_REVISION}
        if catalog["engine"] != expected_engine:
            raise PreregistrationError("catalog engine pin mismatch")
        if not isinstance(manifest["cases"], list) or not manifest["cases"]:
            raise PreregistrationError("manifest cases must be a nonempty list")
        cases, profiles, specs = [], [], {}
        for declaration in manifest["cases"]:
            mapping(declaration, "case", {"case_id", "spec_path", "profile_path", "variants"})
            cid = string(declaration["case_id"], "case id")
            if cid in specs:
                raise PreregistrationError("duplicate manifest case")
            spec_bytes = asset(declaration["spec_path"])
            spec = parse_attack_spec(load_mapping_bytes(spec_bytes, source_path=declaration["spec_path"]))
            if spec.schema_version != V2 or spec.attack_id != cid:
                raise PreregistrationError("case/spec identity mismatch")
            profile_bytes = asset(declaration["profile_path"])
            if not any(declaration["profile_path"].startswith(ref + "/") for ref in closed_roots):
                raise PreregistrationError("profiles require a frozen closed root")
            profile = validate_profile(profile_bytes)
            if (profile["collector_path"] not in manifest["contract_paths"]
                    or digest(asset(profile["collector_path"])) != profile["collector_sha256"]):
                raise PreregistrationError("collector is not the frozen execution contract")
            if spec.runner_protocol != {"profile_id": profile["profile_id"],
                    "profile_sha256": digest(profile_bytes), "baseline_assertion": profile["baseline_assertion"]}:
                raise PreregistrationError("case/profile identity mismatch")
            deps_path = profile["dependencies"]["lock_path"]
            dependency_sha = digest(asset(deps_path))
            twin = spec.adjudication["twin"]
            roles = {"baseline", "attack", "repair"} | ({"twin"} if twin else set())
            variants = mapping(declaration["variants"], "variants", roles)
            arm_bindings = {}
            variant_bytes = {}
            for role, variant in variants.items():
                mapping(variant, "variant", {"root", "production_paths"})
                ref = relative_path(variant["root"], "variant root")
                if ref not in closed_roots:
                    raise PreregistrationError("every variant needs an explicit closed root")
                file_map = {path[len(ref) + 1:]: digest(data) for path, data in files.items()
                            if path.startswith(ref + "/")}
                variant_bytes[role] = {path[len(ref) + 1:]: data for path, data in files.items()
                                       if path.startswith(ref + "/")}
                prod_paths = strings(variant["production_paths"], "production paths")
                for path in prod_paths:
                    relative_path(path, "production path")
                    if path not in file_map:
                        raise PreregistrationError("production path missing from variant")
                command = profile["arms"][role]
                configs = {}
                for path in command["config_paths"]:
                    if path not in file_map:
                        raise PreregistrationError("configuration missing from frozen variant")
                    configs[path] = file_map[path]
                arm_bindings[role] = {"files": file_map, "tree_sha256": canonical_digest(file_map),
                    "production": {path: file_map[path] for path in prod_paths}, "config": configs}
            base = arm_bindings["baseline"]
            if derive_variant(variant_bytes["baseline"], spec.mutations) != variant_bytes["attack"]:
                raise PreregistrationError("attack variant is not derived from the declared mutations")
            for role in roles - {"baseline", "repair"}:
                if arm_bindings[role]["production"] != base["production"]:
                    raise PreregistrationError("attack/twin must retain the identical bug production")
            repair = arm_bindings["repair"]
            if repair["production"].keys() != base["production"].keys() or repair["production"] == base["production"]:
                raise PreregistrationError("repair must calibrate changed production at the same paths")
            without_prod = lambda arm: {key: val for key, val in arm["files"].items() if key not in arm["production"]}
            if without_prod(repair) != without_prod(base):
                raise PreregistrationError("repair must retain the original tests and other inputs")
            specs[cid] = spec
            profiles.append((cid, profile_bytes))
            cases.append({"case_id": cid, "run_id": request.run_id + ":" + cid,
                "spec_sha256": digest(spec_bytes), "profile_id": profile["profile_id"],
                "profile_sha256": digest(profile_bytes), "dependency_lock_sha256": dependency_sha,
                "preregistered_class": spec.adjudication["preregistered_class"],
                "control_role": spec.adjudication["control_role"],
                "twin_case_id": twin["case_id"] if twin else None, "arms": arm_bindings})
        if [case["case_id"] for case in cases] != ids:
            raise PreregistrationError("manifest must preserve the entire ordered catalog denominator")
        rows = {row["id"]: row for row in index["entries"]}
        for cid, spec in specs.items():
            for row in spec.adjudication["residual_mapping"]["row_refs"]:
                if row not in rows or (spec.adjudication["residual_mapping"]["status"] == "matched_residual"
                        and rows[row]["status"] != "documented_residual"):
                    raise PreregistrationError("residual mapping contradicts the pinned index")
            twin = spec.adjudication["twin"]
            if twin:
                control = specs.get(twin["case_id"])
                if (control is None or control.adjudication["preregistered_class"] != "CTL"
                        or control.adjudication["control_role"] != "detectable_attack_control"
                        or control.adjudication["expected_verifier_outcome"] != "block"
                        or control.adjudication["twin"] is not None
                        or control.runner_protocol != spec.runner_protocol):
                    raise PreregistrationError("frozen twin contract mismatch")
                parent = next(case for case in cases if case["case_id"] == cid)
                child = next(case for case in cases if case["case_id"] == twin["case_id"])
                if (parent["arms"]["twin"] != child["arms"]["attack"]
                        or parent["arms"]["baseline"] != child["arms"]["baseline"]
                        or parent["arms"]["repair"] != child["arms"]["repair"]):
                    raise PreregistrationError("twin must share the exact baseline/repair and control attack variant")
        lock = {"protocol": PROTOCOL, **request.payload(), "request_sha256": canonical_digest(request.payload()),
                "catalog_sha256": digest(catalog_bytes), "engine": expected_engine,
                "residual_index_sha256": digest(index_bytes), "approval_provider": approval.provider_id,
                "cases": cases}
        lock["lock_digest"] = canonical_digest(lock)
        return PreparedRun(request, manifest_bytes,
                           json.dumps(lock, sort_keys=True, allow_nan=False).encode("utf-8"), tuple(profiles), tuple(files.items()))
    except (ValueError, OSError, KeyError, TypeError, AttackSchemaError, subprocess.SubprocessError) as exc:
        if isinstance(exc, PreregistrationError):
            raise
        raise PreregistrationError(str(exc)) from exc


def case_binding(lock: dict, case_id: str) -> dict:
    """One canonical identity for receipts and every case-bound ledger event."""
    case = next((item for item in lock["cases"] if item["case_id"] == case_id), None)
    if case is None:
        raise PreregistrationError(f"undeclared case: {case_id}")
    result = {key: lock[key] for key in ("campaign_id", "request_id", "phase1_commit", "source_commit",
                                       "manifest_sha256", "lock_digest")}
    result.update({key: case[key] for key in ("run_id", "case_id", "spec_sha256", "profile_id",
                                             "profile_sha256", "dependency_lock_sha256")})
    result["arms_sha256"] = canonical_digest(case["arms"])
    return result
