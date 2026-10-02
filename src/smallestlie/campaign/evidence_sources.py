"""Independent immutable EC publication and accepted outer-supervisor sources.

The integration caller imports exact publication/collector acceptance grants
from outside the product checkout. Generic EC receipts and job success do not
attest fixture execution. No grant is discovered in a receipt or replay bundle.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Protocol

from smallestlie.adjudication.observations import TrustedVerifierEnvelope
from smallestlie.attacks.adjudication import mapping, sha256, string
from smallestlie.campaign.preregistration import (
    PreparedRun, canonical_digest, case_binding, commit, digest, integer, json_mapping,
)
from smallestlie.campaign.provenance import (
    GitHubObjectReader, GitHubTransport, GovernanceTransport, ProvenanceError,
    _path, _repository, decode_git_blob,
)
from smallestlie.oracle.runner_evidence import TrustedExecutionEnvelope, _absolute

PROVIDER = "ec-immutable-supervisor/v1"
MAX_FILES, MAX_TREES, MAX_TOTAL_BYTES = 256, 64, 50_000_000


class ReceiptTransport(GovernanceTransport, Protocol):
    def workflow_run(self, repository: str, run_id: int, attempt: int) -> dict: ...
    def workflow_job(self, repository: str, job_id: int) -> dict: ...


def _artifact_path(value: str) -> str:
    _path(value)
    for part in value.split("/"):
        if part.endswith(".") or re.fullmatch(r"(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", part):
            raise ProvenanceError("ambiguous cross-platform artifact path")
    return value


@dataclass(frozen=True)
class EcPublicationGrant:
    """Exact externally accepted publication, optionally accepted supervisor.

    supervisor_sha256 must be granted only after accepting the actual outer
    collector's measurement, isolation and output-completion contract. Merely
    accepting a generic EC publication never grants those facts.
    """

    request_sha256: str
    lock_digest: str
    source_commit: str
    ec_source_commit: str
    run_id: int
    attempt: int
    job_id: int
    receipt_commit: str
    publication_sha256: str
    acceptance_ref: str
    supervisor_sha256: str | None = None
    supervisor_acceptance_ref: str | None = None

    def __post_init__(self) -> None:
        for key in ("request_sha256", "lock_digest", "publication_sha256"):
            sha256(getattr(self, key), key)
        for key in ("source_commit", "ec_source_commit", "receipt_commit"):
            commit(getattr(self, key), key)
        for key in ("run_id", "attempt", "job_id"):
            integer(getattr(self, key), key, minimum=1)
        string(self.acceptance_ref, "external publication acceptance")
        if self.supervisor_sha256 is not None:
            sha256(self.supervisor_sha256, "externally accepted outer supervisor")
            string(self.supervisor_acceptance_ref, "independent outer collector acceptance")
        elif self.supervisor_acceptance_ref is not None:
            raise ProvenanceError("collector acceptance requires exact supervisor bytes")


@dataclass(frozen=True)
class EcReceiptTrustRoot:
    repository: str
    repository_id: int
    product_repository: str
    workflow_id: int
    workflow_path: str
    workflow_sha256: str
    base_branch: str
    job_name: str
    host: str
    runner_id: int
    runner_name: str
    generation: str
    workload: str
    declaration_sha256: str
    collector_path: str
    collector_sha256: str
    verifier_runtime_name: str
    verifier_runtime_version: str
    verifier_runtime_sha256: str
    verifier_semantic_env: tuple[tuple[str, str], ...]
    publications: tuple[EcPublicationGrant, ...]

    def __post_init__(self) -> None:
        _repository(self.repository)
        _repository(self.product_repository)
        if self.repository == self.product_repository:
            raise ProvenanceError("collector publication source must be independent of product")
        for key in ("repository_id", "workflow_id", "runner_id"):
            integer(getattr(self, key), key, minimum=1)
        for key in ("workflow_path", "collector_path"):
            _artifact_path(getattr(self, key))
        for key in ("workflow_sha256", "collector_sha256", "declaration_sha256", "verifier_runtime_sha256"):
            sha256(getattr(self, key), key)
        for key in ("base_branch", "job_name", "host", "runner_name", "generation", "workload",
                    "verifier_runtime_name", "verifier_runtime_version"):
            string(getattr(self, key), key)
        if type(self.verifier_semantic_env) is not tuple:
            raise ProvenanceError("explicit immutable verifier environment required")
        names = []
        for pair in self.verifier_semantic_env:
            if type(pair) is not tuple or len(pair) != 2:
                raise ProvenanceError("invalid verifier environment")
            string(pair[0], "environment key")
            if not isinstance(pair[1], str):
                raise ProvenanceError("invalid verifier environment value")
            names.append(pair[0].upper())
        if len(names) != len(set(names)):
            raise ProvenanceError("ambiguous verifier environment keys")
        if (type(self.publications) is not tuple or not self.publications
                or any(not isinstance(item, EcPublicationGrant) for item in self.publications)):
            raise ProvenanceError("independent exact publication acceptance required")
        identities = [(item.request_sha256, item.lock_digest) for item in self.publications]
        if len(identities) != len(set(identities)):
            raise ProvenanceError("ambiguous publication registry")


@dataclass(frozen=True)
class VerifiedEcReceipt:
    grant: EcPublicationGrant
    files: tuple[tuple[str, bytes], ...]

    def artifact(self, path: str) -> bytes:
        _artifact_path(path)
        for name, data in self.files:
            if name == path:
                return data
        raise ProvenanceError("immutable artifact missing")


class EcReceiptStore:
    """Read accepted raw bytes and independently cross-check exact dispatch."""

    def __init__(self, root: EcReceiptTrustRoot, *, transport: ReceiptTransport | None = None):
        if not isinstance(root, EcReceiptTrustRoot):
            raise ProvenanceError("independent receipt trust root required")
        self.root = root
        self.transport = transport if transport is not None else GitHubTransport()
        self.reader = GitHubObjectReader(transport=self.transport)

    def _files(self, revision: str) -> dict[str, bytes]:
        repo = self.root.repository
        obj = self.transport.git_commit(repo, revision)
        if not isinstance(obj, dict) or obj.get("sha") != revision or not isinstance(obj.get("tree"), dict):
            raise ProvenanceError("receipt commit identity mismatch")
        pending = [("", commit(obj["tree"].get("sha"), "receipt tree"), 0)]
        objects, aliases, visited = {}, set(), 0
        while pending:
            prefix, tree_id, depth = pending.pop()
            visited += 1
            if visited > MAX_TREES or depth > 32:
                raise ProvenanceError("receipt tree traversal limit exceeded")
            tree = self.transport.tree(repo, tree_id)
            if (not isinstance(tree, dict) or tree.get("sha") != tree_id
                    or tree.get("truncated") is not False or not isinstance(tree.get("tree"), list)
                    or not tree["tree"] or len(tree["tree"]) > MAX_FILES):
                raise ProvenanceError("incomplete receipt tree")
            for item in tree["tree"]:
                if not isinstance(item, dict):
                    raise ProvenanceError("invalid receipt entry")
                name = item.get("path")
                if not isinstance(name, str) or "/" in name:
                    raise ProvenanceError("nonrecursive receipt tree required")
                path = _artifact_path(prefix + name)
                alias = path.casefold()
                if alias in aliases:
                    raise ProvenanceError("duplicate or aliased receipt path")
                aliases.add(alias)
                oid = commit(item.get("sha"), "receipt object")
                if item.get("type") == "tree" and item.get("mode") == "040000":
                    pending.append((path + "/", oid, depth + 1))
                elif item.get("type") == "blob" and item.get("mode") in {"100644", "100755"}:
                    objects[path] = oid
                else:
                    raise ProvenanceError("receipt links/submodules are not regular artifacts")
                if len(objects) + len(aliases) > 2 * MAX_FILES:
                    raise ProvenanceError("receipt inventory limit exceeded")
        result, total = {}, 0
        for path, oid in sorted(objects.items()):
            data = decode_git_blob(self.transport.blob(repo, oid), oid)
            total += len(data)
            if total > MAX_TOTAL_BYTES:
                raise ProvenanceError("receipt total byte limit exceeded")
            result[path] = data
        return result

    def read(self, prepared: PreparedRun) -> VerifiedEcReceipt:
        lock = prepared.lock()
        request_sha = canonical_digest(prepared.request.payload())
        grant = next((item for item in self.root.publications
                      if item.request_sha256 == request_sha and item.lock_digest == lock["lock_digest"]), None)
        if grant is None or grant.source_commit != prepared.request.source_commit:
            raise ProvenanceError("exact formal request publication not accepted")
        root = self.root
        run = self.transport.workflow_run(root.repository, grant.run_id, grant.attempt)
        job = self.transport.workflow_job(root.repository, grant.job_id)
        if not isinstance(run, dict) or not isinstance(job, dict):
            raise ProvenanceError("invalid dispatch API response")
        repository = run.get("repository")
        if (not isinstance(repository, dict) or type(repository.get("id")) is not int
                or repository["id"] != root.repository_id or repository.get("full_name") != root.repository):
            raise ProvenanceError("dispatch repository identity mismatch")
        for key, expected in (("id", grant.run_id), ("run_attempt", grant.attempt), ("workflow_id", root.workflow_id)):
            if type(run.get(key)) is not int or run[key] != expected:
                raise ProvenanceError("exact workflow run/attempt identity mismatch")
        for key, expected in (("id", grant.job_id), ("run_id", grant.run_id),
                              ("run_attempt", grant.attempt), ("runner_id", root.runner_id)):
            if type(job.get(key)) is not int or job[key] != expected:
                raise ProvenanceError("exact numeric job/runner identity mismatch")
        if (run.get("head_sha") != grant.ec_source_commit or run.get("path") != root.workflow_path
                or run.get("head_branch") != root.base_branch or run.get("event") != "workflow_dispatch"
                or run.get("status") != "completed" or job.get("status") != "completed"
                or job.get("head_sha") != grant.ec_source_commit or job.get("name") != root.job_name
                or job.get("runner_name") != root.runner_name
                or run.get("conclusion") not in {"success", "failure", "cancelled", "timed_out"}
                or job.get("conclusion") not in {"success", "failure", "cancelled", "timed_out"}):
            raise ProvenanceError("dispatch source/workflow/host/completion mismatch")
        for path, expected in ((root.workflow_path, root.workflow_sha256), (root.collector_path, root.collector_sha256)):
            if digest(self.reader.blob_at(root.repository, grant.ec_source_commit, path)) != expected:
                raise ProvenanceError("executed workflow/outer collector source pin mismatch")
        files = self._files(grant.receipt_commit)
        publication = files.get("ec-publication.json")
        if publication is None or digest(publication) != grant.publication_sha256:
            raise ProvenanceError("accepted publication bytes mismatch")
        raw = json_mapping(publication, "EC publication")
        mapping(raw, "EC publication", {"schema_version", "status", "context", "files"})
        if type(raw["schema_version"]) is not int or raw["schema_version"] != 1 or raw["status"] != "preserved":
            raise ProvenanceError("unsupported EC publication")
        context = raw["context"]
        expected_context = {"GITHUB_RUN_ID": str(grant.run_id), "GITHUB_RUN_ATTEMPT": str(grant.attempt),
                            "GITHUB_SHA": grant.ec_source_commit, "GITHUB_JOB": root.job_name,
                            "COMPUTERNAME": root.host, "EC_JOB_STATUS": job["conclusion"]}
        if not isinstance(context, dict) or any(context.get(key) != val for key, val in expected_context.items()):
            raise ProvenanceError("publication dispatch context mismatch")
        if not isinstance(raw["files"], list) or not raw["files"] or len(raw["files"]) >= MAX_FILES:
            raise ProvenanceError("publication inventory missing or too large")
        inventory = set()
        for item in raw["files"]:
            mapping(item, "published artifact", {"path", "bytes", "sha256"})
            path = _artifact_path(item["path"])
            integer(item["bytes"], "published byte count")
            sha256(item["sha256"], "published raw digest")
            if (path in inventory or path == "ec-publication.json" or path not in files
                    or len(files[path]) != item["bytes"] or digest(files[path]) != item["sha256"]):
                raise ProvenanceError("publication raw byte inventory mismatch")
            inventory.add(path)
        if inventory != files.keys() - {"ec-publication.json"}:
            raise ProvenanceError("publication omits or adds receipt artifacts")
        workload = json_mapping(files.get("ec-workload.json"), "EC workload context")
        expected = {"repository": root.product_repository, "sha": grant.source_commit,
                    "ec_sha": grant.ec_source_commit, "run_id": str(grant.run_id), "run_attempt": str(grant.attempt),
                    "host": root.host, "runner": root.runner_name, "generation": root.generation,
                    "workload": root.workload, "declaration_sha256": root.declaration_sha256,
                    "mode": "single", "cache": False}
        if (type(workload.get("schema_version")) is not int or workload["schema_version"] != 1
                or any(workload.get(key) != val for key, val in expected.items())
                or workload.get("cache") is not False):
            raise ProvenanceError("workload/source/declaration context mismatch")
        # result.passed, QoS, ec_task disposition and outer exit are not arm facts.
        return VerifiedEcReceipt(grant, tuple(sorted(files.items())))

    def supervisor(self, prepared: PreparedRun) -> tuple[VerifiedEcReceipt, dict]:
        receipt = self.read(prepared)
        if receipt.grant.supervisor_sha256 is None:
            raise ProvenanceError("outer supervisor acceptance missing")
        data = receipt.artifact("m12-supervisor.json")
        if digest(data) != receipt.grant.supervisor_sha256:
            raise ProvenanceError("accepted outer supervisor bytes mismatch")
        raw = json_mapping(data, "outer supervisor")
        mapping(raw, "outer supervisor", {"schema_version", "request", "request_sha256", "lock_digest",
                "collector_sha256", "source_run_id", "job_id", "host", "lock_sequence", "cases"})
        if (raw["schema_version"] != "smallestlie.outer-supervisor/v1"
                or raw["request"] != prepared.request.payload()
                or raw["request_sha256"] != receipt.grant.request_sha256
                or raw["lock_digest"] != receipt.grant.lock_digest
                or raw["collector_sha256"] != self.root.collector_sha256
                or raw["source_run_id"] != str(receipt.grant.run_id)
                or raw["job_id"] != str(receipt.grant.job_id) or raw["host"] != self.root.host):
            raise ProvenanceError("outer supervisor formal binding mismatch")
        integer(raw["lock_sequence"], "supervisor observed lock sequence", minimum=1)
        cases = raw["cases"]
        expected_ids = {item["case_id"] for item in prepared.lock()["cases"]}
        if not isinstance(cases, list) or len(cases) != len(expected_ids):
            raise ProvenanceError("supervisor drops frozen cases")
        seen = set()
        command_sequences = set()
        for item in cases:
            mapping(item, "supervised case", {"binding", "runner", "verifier"})
            if not isinstance(item["binding"], dict):
                raise ProvenanceError("invalid supervised case binding")
            cid = item["binding"].get("case_id")
            if cid not in expected_ids or cid in seen or item["binding"] != case_binding(prepared.lock(), cid):
                raise ProvenanceError("duplicate or mismatched supervised case")
            seen.add(cid)
            records = []
            if isinstance(item["runner"], dict) and isinstance(item["runner"].get("arms"), dict):
                records.extend(item["runner"]["arms"].values())
            if isinstance(item["verifier"], dict):
                records.append(item["verifier"])
            for record in records:
                if not isinstance(record, dict):
                    raise ProvenanceError("invalid supervised command")
                sequence = integer(record.get("command_sequence"), "unique command sequence", minimum=1)
                if sequence <= raw["lock_sequence"] or sequence in command_sequences:
                    raise ProvenanceError("supervisor command preceded lock or reused reservation")
                command_sequences.add(sequence)
        return receipt, raw


def _case(supervisor: dict, case_id: str) -> dict:
    return next(item for item in supervisor["cases"] if item["binding"]["case_id"] == case_id)


def _artifact(receipt: VerifiedEcReceipt, ref: dict) -> bytes:
    mapping(ref, "supervisor artifact", {"path", "sha256"})
    sha256(ref["sha256"], "supervisor artifact digest")
    data = receipt.artifact(ref["path"])
    if digest(data) != ref["sha256"]:
        raise ProvenanceError("supervisor artifact byte mismatch")
    return data


def _completion(record: dict, lock_sequence: int) -> tuple[int, str, int | None]:
    sequence = integer(record.get("command_sequence"), "observed command sequence", minimum=1)
    kind, code = record.get("termination_kind"), record.get("exit_code")
    if (sequence <= lock_sequence or record.get("output_complete") is not True
            or record.get("descendants_reaped") is not True
            or kind not in {"completed", "timeout", "spawn_error", "signal", "internal_error"}
            or (code is not None and type(code) is not int) or (kind == "completed" and code is None)):
        raise ProvenanceError("supervisor completion/launch order incomplete")
    return sequence, kind, code


class EcExecutionAuthority:
    def __init__(self, store: EcReceiptStore):
        if not isinstance(store, EcReceiptStore):
            raise ProvenanceError("configured receipt store required")
        self.store = store

    def verify(self, prepared: PreparedRun, case_id: str, receipt_sha256: str) -> TrustedExecutionEnvelope | None:
        try:
            receipt, supervisor = self.store.supervisor(prepared)
            record = _case(supervisor, case_id)["runner"]
            mapping(record, "supervised runner", {"receipt", "arms"})
            data = _artifact(receipt, record["receipt"])
            if digest(data) != receipt_sha256:
                raise ProvenanceError("runner receipt source mismatch")
            raw = json_mapping(data, "captured runner receipt")
            profile = prepared.profile(case_id)
            if profile["collector_sha256"] != supervisor["collector_sha256"]:
                raise ProvenanceError("actually launched collector differs from frozen profile")
            arms = record["arms"]
            roles = prepared.binding(case_id)["arms"].keys()
            mapping(arms, "supervised arms", set(roles))
            if raw.get("arms") != {role: arms[role]["observation"] for role in roles}:
                raise ProvenanceError("receipt differs from independent measured arm facts")
            exits, sequences = [], []
            for role, item in arms.items():
                mapping(item, "supervised arm", {"observation", "command_sequence", "termination_kind",
                        "exit_code", "output_complete", "descendants_reaped"})
                sequence, kind, code = _completion(item, supervisor["lock_sequence"])
                if not isinstance(item["observation"], dict):
                    raise ProvenanceError("measured arm observation missing")
                if (item["observation"].get("termination_kind"), item["observation"].get("exit_code")) != (kind, code):
                    raise ProvenanceError("runner observation contradicts supervisor disposition")
                for key in ("stdout", "stderr", "report"):
                    _artifact(receipt, item["observation"][key])
                exits.append((role, kind, code))
                sequences.append(sequence)
            if len(set(sequences)) != len(sequences):
                raise ProvenanceError("runner launch reservation reused")
            return TrustedExecutionEnvelope(PROVIDER, receipt.grant.receipt_commit,
                supervisor["request_sha256"], _case(supervisor, case_id)["binding"]["run_id"],
                supervisor["source_run_id"], supervisor["job_id"], supervisor["host"],
                supervisor["request"]["phase1_commit"], supervisor["request"]["source_commit"],
                supervisor["lock_digest"], digest(data), supervisor["collector_sha256"],
                supervisor["lock_sequence"], min(sequences), tuple(exits))
        except (ValueError, TypeError, KeyError, OSError, StopIteration, AttributeError):
            return None


class EcVerifierAuthority:
    """Initial policy support: a base tree with no Checkwash policy directory.

    Such an independently measured complete tree uses v0.5.0 defaults (high,
    no allowlist). Configured policies stay unknown until their resolver is
    implemented; metadata cannot supply its own effective threshold.
    """

    def __init__(self, store: EcReceiptStore):
        if not isinstance(store, EcReceiptStore):
            raise ProvenanceError("configured receipt store required")
        self.store = store

    def verify(self, prepared: PreparedRun, case_id: str, metadata_sha256: str) -> TrustedVerifierEnvelope | None:
        try:
            receipt, supervisor = self.store.supervisor(prepared)
            record = _case(supervisor, case_id)["verifier"]
            mapping(record, "supervised verifier", {"metadata", "stdout", "stderr", "baseline_files", "attack_files",
                    "engine_sha256", "runtime", "runtime_path", "engine_path", "semantic_env", "workspace_root",
                    "argv", "cwd", "logical_cwd", "base_commit", "head_commit", "fail_on", "command_sequence",
                    "termination_kind", "exit_code", "output_complete", "descendants_reaped"})
            data = _artifact(receipt, record["metadata"])
            if digest(data) != metadata_sha256:
                raise ProvenanceError("verifier metadata source mismatch")
            stdout, stderr = _artifact(receipt, record["stdout"]), _artifact(receipt, record["stderr"])
            case = prepared.binding(case_id)
            for role in ("baseline", "attack"):
                if record[role + "_files"] != case["arms"][role]["files"]:
                    raise ProvenanceError("observed complete Git tree differs from frozen variant")
            if any(path == directory or path.startswith(directory + "/")
                   for path in record["baseline_files"] for directory in (".checkwash", ".greenwash")):
                raise ProvenanceError("configured Checkwash policy not yet supported")
            root = self.store.root
            runtime = {"name": root.verifier_runtime_name, "version": root.verifier_runtime_version,
                       "artifact_sha256": root.verifier_runtime_sha256}
            if (record["runtime"] != runtime or record["semantic_env"] != dict(root.verifier_semantic_env)
                    or record["engine_sha256"] != prepared.lock()["engine"]["artifact_sha256"]
                    or record["fail_on"] != "high"):
                raise ProvenanceError("observed verifier runtime/environment/artifact/policy mismatch")
            native = json_mapping(stdout, "captured Checkwash stdout")
            if (not isinstance(native.get("findings"), list)
                    or any(not isinstance(item, dict) or item.get("allowlisted") is not False
                           for item in native["findings"])):
                raise ProvenanceError("native allowlist flags contradict independently observed default policy")
            workspace = _absolute(record["workspace_root"])
            runtime_path, engine_path = _absolute(record["runtime_path"]), _absolute(record["engine_path"])
            argv = [runtime_path, engine_path, "check", "HEAD~1..HEAD", "--format", "json"]
            if record["argv"] != argv or record["cwd"] != workspace or record["logical_cwd"] != ".":
                raise ProvenanceError("actual verifier command/workspace mismatch")
            base, head = commit(record["base_commit"], "observed base"), commit(record["head_commit"], "observed head")
            if base == head:
                raise ProvenanceError("observed range has no mutant")
            sequence, kind, code = _completion(record, supervisor["lock_sequence"])
            return TrustedVerifierEnvelope(PROVIDER, receipt.grant.receipt_commit,
                canonical_digest(_case(supervisor, case_id)["binding"]), digest(data), digest(stdout), digest(stderr),
                canonical_digest(record["baseline_files"]), canonical_digest(record["attack_files"]),
                record["engine_sha256"], base, head, tuple(record["argv"]), record["logical_cwd"],
                record["fail_on"], kind, code, supervisor["lock_sequence"], sequence)
        except (ValueError, TypeError, KeyError, OSError, StopIteration, AttributeError):
            return None
