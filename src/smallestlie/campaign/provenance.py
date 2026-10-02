"""Independent GitHub approval sources for formal preregistration.

The caller configures trust roots outside the product checkout or replay bundle.
Only merged changes approved by those roots authorize a request. This module
does not authenticate execution, verifier captures or semantic reviews.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import re
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from smallestlie.attacks.adjudication import mapping, relative_path, sha256, string
from smallestlie.campaign.preregistration import (
    PreregistrationApproval, PreregistrationError, RunRequest, canonical_digest,
    commit, digest, integer, json_mapping,
)
from smallestlie.verdict.json_input import read_json

MAX_BYTES = 10_000_000
PROVIDER = "github-governance/v1"
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")


class ProvenanceError(PreregistrationError):
    pass


def _repository(value: str) -> str:
    if not isinstance(value, str) or not _REPOSITORY.fullmatch(value):
        raise ProvenanceError("invalid GitHub repository")
    if any(part in {".", ".."} for part in value.split("/")):
        raise ProvenanceError("invalid GitHub repository")
    return value


def _path(value: str) -> str:
    relative_path(value, "governance blob path")
    if not re.fullmatch(r"[A-Za-z0-9_./-]+", value) or ".git" in value.split("/"):
        raise ProvenanceError("unsupported governance blob path")
    return value


@dataclass(frozen=True)
class RepositoryTrust:
    full_name: str
    repository_id: int
    base_branch: str
    merger_ids: frozenset[int]

    def __post_init__(self) -> None:
        _repository(self.full_name)
        integer(self.repository_id, "repository ID", minimum=1)
        string(self.base_branch, "approved base branch")
        if type(self.merger_ids) is not frozenset or not self.merger_ids:
            raise ProvenanceError("explicit human merger IDs required")
        for actor in self.merger_ids:
            integer(actor, "human merger ID", minimum=1)


@dataclass(frozen=True)
class HumanMergeApproval:
    """Exact approval imported by the trusted human-input/governance process.

    GitHub's User type does not distinguish a human from automation using a PAT.
    Neither account membership nor a record's own claims can create this grant.
    """

    repository_id: int
    pull_request: int
    merge_commit: str
    merger_id: int
    reference: str

    def __post_init__(self) -> None:
        integer(self.repository_id, "approval repository ID", minimum=1)
        integer(self.pull_request, "approved PR", minimum=1)
        commit(self.merge_commit, "human-approved merge commit")
        integer(self.merger_id, "approved merger ID", minimum=1)
        string(self.reference, "independent human approval reference")


@dataclass(frozen=True)
class GovernanceTrustRoot:
    product: RepositoryTrust
    requests: RepositoryTrust
    human_approvals: tuple[HumanMergeApproval, ...]

    def __post_init__(self) -> None:
        if not all(isinstance(root, RepositoryTrust) for root in (self.product, self.requests)):
            raise ProvenanceError("explicit repository trust roots required")
        if (self.product.full_name == self.requests.full_name
                or self.product.repository_id == self.requests.repository_id):
            raise ProvenanceError("request governance must be independent of product inputs")
        if (type(self.human_approvals) is not tuple or not self.human_approvals
                or any(not isinstance(item, HumanMergeApproval) for item in self.human_approvals)):
            raise ProvenanceError("independent exact human approvals required")
        identities = [(item.repository_id, item.pull_request) for item in self.human_approvals]
        if len(set(identities)) != len(identities):
            raise ProvenanceError("ambiguous human approval registry")
        for item in self.human_approvals:
            trust = next((root for root in (self.product, self.requests)
                          if root.repository_id == item.repository_id), None)
            if trust is None or item.merger_id not in trust.merger_ids:
                raise ProvenanceError("human approval outside repository/account trust roots")


class GovernanceTransport(Protocol):
    """Authenticated API responses, never records supplied by an attack."""

    def pull_request(self, repository: str, number: int) -> dict: ...
    def pull_files(self, repository: str, number: int, page: int) -> list: ...
    def git_commit(self, repository: str, revision: str) -> dict: ...
    def tree(self, repository: str, object_id: str) -> dict: ...
    def blob(self, repository: str, object_id: str) -> dict: ...


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never send governance credentials to another host or follow a rename.
        return None


class GitHubTransport:
    """GET-only production transport to the fixed public GitHub API origin.

    Supply a read-only credential from the governance process for private repos.
    No environment, product-file or bundle credential discovery is performed.
    """

    def __init__(self, *, token: str | None = None) -> None:
        if token is not None and (not isinstance(token, str) or not token
                                  or any(ord(char) < 33 or ord(char) > 126 for char in token)):
            raise ProvenanceError("invalid GitHub credential")
        self._token = token

    def _get(self, endpoint: str):
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "smallestlie-governance",
                   "X-GitHub-Api-Version": "2026-03-10"}
        if self._token is not None:
            headers["Authorization"] = "Bearer " + self._token
        request = Request("https://api.github.com/" + endpoint, headers=headers, method="GET")
        try:
            with build_opener(_NoRedirect()).open(request, timeout=15) as response:
                if response.status != 200:
                    raise ProvenanceError("GitHub approval read failed")
                data = response.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise ProvenanceError("GitHub response exceeds size limit")
            return read_json(data.decode("utf-8"))
        except (HTTPError, URLError, OSError, ValueError, UnicodeError):
            # Do not include response bodies, credentials or attacker text.
            raise ProvenanceError("GitHub approval source unavailable or invalid") from None

    def pull_request(self, repository: str, number: int) -> dict:
        integer(number, "PR number", minimum=1)
        return self._get(f"repos/{_repository(repository)}/pulls/{number}")

    def pull_files(self, repository: str, number: int, page: int) -> list:
        integer(number, "PR number", minimum=1)
        integer(page, "PR file page", minimum=1)
        return self._get(f"repos/{_repository(repository)}/pulls/{number}/files?per_page=100&page={page}")

    def git_commit(self, repository: str, revision: str) -> dict:
        commit(revision, "immutable merge commit")
        return self._get(f"repos/{_repository(repository)}/git/commits/{revision}")

    def tree(self, repository: str, object_id: str) -> dict:
        commit(object_id, "immutable tree")
        return self._get(f"repos/{_repository(repository)}/git/trees/{object_id}")

    def blob(self, repository: str, object_id: str) -> dict:
        commit(object_id, "immutable blob")
        return self._get(f"repos/{_repository(repository)}/git/blobs/{object_id}")


@dataclass(frozen=True)
class GovernanceReference:
    repository: str
    pull_request: int
    path: str

    @classmethod
    def parse(cls, reference: str) -> GovernanceReference:
        if not isinstance(reference, str) or len(reference) > 2048:
            raise ProvenanceError("governance reference required")
        match = re.fullmatch(r"github-pr://([^/]+/[^/]+)/([1-9][0-9]*)/(.+)", reference)
        if match is None:
            raise ProvenanceError("governance reference must identify a PR and blob path")
        return cls(_repository(match[1]), int(match[2]), _path(match[3]))

    def render(self) -> str:
        return f"github-pr://{self.repository}/{self.pull_request}/{self.path}"


@dataclass(frozen=True)
class VerifiedGovernanceBlob:
    reference: str
    repository_id: int
    merger_id: int
    merge_commit: str
    blob_sha: str
    data: bytes
    human_approval_ref: str

    @property
    def sha256(self) -> str:
        return digest(self.data)


class GitHubGovernanceStore:
    def __init__(self, root: GovernanceTrustRoot, *, transport: GovernanceTransport | None = None):
        if not isinstance(root, GovernanceTrustRoot):
            raise ProvenanceError("governance trust root is not configured")
        self.root = root
        self.transport = transport if transport is not None else GitHubTransport()

    def _merged(self, ref: GovernanceReference, trust: RepositoryTrust) -> tuple[str, int, str]:
        if ref.repository != trust.full_name:
            raise ProvenanceError("wrong approval repository or role")
        pr = self.transport.pull_request(ref.repository, ref.pull_request)
        if not isinstance(pr, dict):
            raise ProvenanceError("invalid GitHub PR response")
        base, actor = pr.get("base"), pr.get("merged_by")
        repo = base.get("repo") if isinstance(base, dict) else None
        if (type(pr.get("number")) is not int or pr["number"] != ref.pull_request
                or pr.get("merged") is not True or pr.get("state") != "closed"
                or not isinstance(pr.get("merged_at"), str) or not pr["merged_at"]
                or not isinstance(repo, dict) or type(repo.get("id")) is not int
                or repo["id"] != trust.repository_id or repo.get("full_name") != trust.full_name
                or base.get("ref") != trust.base_branch
                or not isinstance(actor, dict) or actor.get("type") != "User"
                or type(actor.get("id")) is not int or actor["id"] not in trust.merger_ids):
            raise ProvenanceError("PR is not an approved human merge at the trusted destination")
        revision = commit(pr.get("merge_commit_sha"), "PR merge commit")
        approval = next((item for item in self.root.human_approvals
                         if item.repository_id == trust.repository_id
                         and item.pull_request == ref.pull_request), None)
        if (approval is None or approval.merge_commit != revision or approval.merger_id != actor["id"]):
            raise ProvenanceError("GitHub account action lacks independent exact human approval")
        return revision, actor["id"], approval.reference

    def _blob_at(self, repository: str, revision: str, path: str) -> tuple[str, bytes]:
        obj = self.transport.git_commit(repository, revision)
        if not isinstance(obj, dict) or obj.get("sha") != revision or not isinstance(obj.get("tree"), dict):
            raise ProvenanceError("merge commit identity mismatch")
        tree_id = commit(obj["tree"].get("sha"), "merge tree")
        components = path.split("/")
        if len(components) > 32:
            raise ProvenanceError("governance path too deep")
        for index, name in enumerate(components):
            tree = self.transport.tree(repository, tree_id)
            if (not isinstance(tree, dict) or tree.get("sha") != tree_id
                    or tree.get("truncated") is not False or not isinstance(tree.get("tree"), list)):
                raise ProvenanceError("incomplete or mismatched Git tree")
            entries = tree["tree"]
            if len(entries) > 10_000 or any(not isinstance(item, dict) for item in entries):
                raise ProvenanceError("invalid Git tree entries")
            names = [item.get("path") for item in entries]
            if (any(not isinstance(value, str) or not value or "/" in value or value in {".", ".."}
                    for value in names) or len(set(names)) != len(names)):
                raise ProvenanceError("ambiguous nonrecursive Git tree")
            found = next((item for item in entries if item["path"] == name), None)
            if found is None:
                raise ProvenanceError("approved blob missing at merge commit")
            object_id = commit(found.get("sha"), "tree entry")
            if index < len(components) - 1:
                if found.get("type") != "tree" or found.get("mode") != "040000":
                    raise ProvenanceError("governance parent must be a Git tree")
                tree_id = object_id
            elif found.get("type") != "blob" or found.get("mode") not in {"100644", "100755"}:
                raise ProvenanceError("governance input must be a regular Git blob")
        blob = self.transport.blob(repository, object_id)
        if (not isinstance(blob, dict) or blob.get("sha") != object_id or blob.get("encoding") != "base64"
                or type(blob.get("size")) is not int or not 0 <= blob["size"] <= MAX_BYTES
                or not isinstance(blob.get("content"), str) or len(blob["content"]) > 2 * MAX_BYTES):
            raise ProvenanceError("invalid Git blob response")
        try:
            # GitHub wraps base64 with LF. Other non-base64 characters are rejected.
            data = base64.b64decode(blob["content"].replace("\n", ""), validate=True)
        except ValueError as exc:
            raise ProvenanceError("invalid Git blob encoding") from exc
        actual = hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()
        if len(data) != blob["size"] or actual != object_id:
            raise ProvenanceError("raw Git blob size or object digest mismatch")
        return object_id, data

    def approved_blob(self, reference: str, *, role: str) -> VerifiedGovernanceBlob:
        """Authenticate the exact changed blob approved by the configured role."""
        ref = GovernanceReference.parse(reference)
        trust = {"phase1": self.root.product, "request": self.root.requests}.get(role)
        if trust is None:
            raise ProvenanceError("unconfigured approval role")
        revision, actor, human_ref = self._merged(ref, trust)
        object_id, data = self._blob_at(ref.repository, revision, ref.path)
        files = []
        for page in range(1, 31):
            items = self.transport.pull_files(ref.repository, ref.pull_request, page)
            if not isinstance(items, list) or len(items) > 100 or any(not isinstance(item, dict) for item in items):
                raise ProvenanceError("invalid PR changed-file response")
            files.extend(items)
            if len(items) < 100:
                break
        else:
            raise ProvenanceError("PR file enumeration limit reached")
        names = [item.get("filename") for item in files]
        if any(not isinstance(name, str) for name in names) or len(set(names)) != len(names):
            raise ProvenanceError("ambiguous PR changed-file response")
        changed = [item for item in files if item["filename"] == ref.path]
        if (len(changed) != 1 or changed[0].get("status") not in {"added", "modified"}
                or changed[0].get("sha") != object_id):
            raise ProvenanceError("approval PR did not approve these exact new blob bytes")
        return VerifiedGovernanceBlob(ref.render(), trust.repository_id, actor, revision, object_id, data, human_ref)


class GitHubPreregistrationAuthority:
    """Human-merged Phase 1 plus separately approved, fully bound run request.

    The request record can live in a PR whose number is known before merge,
    avoiding a self-reference to the commit containing its own request digest.
    """

    def __init__(self, store: GitHubGovernanceStore):
        if not isinstance(store, GitHubGovernanceStore):
            raise ProvenanceError("independent governance store required")
        self.store = store

    def verify(self, request: RunRequest) -> PreregistrationApproval | None:
        try:
            if not isinstance(request, RunRequest):
                raise ProvenanceError("formal request required")
            for key in ("campaign_id", "request_id", "run_id", "authorization_ref"):
                string(getattr(request, key), key)
            commit(request.phase1_commit, "Phase-1 commit")
            commit(request.source_commit, "source commit")
            sha256(request.manifest_sha256, "manifest digest")
            approved = self.store.approved_blob(request.authorization_ref, role="request")
            record = json_mapping(approved.data, "approved formal request")
            mapping(record, "formal request", {"schema_version", "kind", "request", "phase1"})
            if (record["schema_version"] != "smallestlie.governance-request/v1"
                    or record["kind"] != "formal-run-authorization"
                    or record["request"] != request.payload()):
                raise ProvenanceError("approved formal request mismatch")
            phase1 = mapping(record["phase1"], "Phase-1 approval", {"pull_request", "manifest_path"})
            number = integer(phase1["pull_request"], "Phase-1 PR", minimum=1)
            ref = GovernanceReference(self.store.root.product.full_name, number, _path(phase1["manifest_path"]))
            manifest = self.store.approved_blob(ref.render(), role="phase1")
            if manifest.merge_commit != request.phase1_commit or manifest.sha256 != request.manifest_sha256:
                raise ProvenanceError("human-merged Phase-1 manifest mismatch")
            return PreregistrationApproval(PROVIDER, request.authorization_ref, manifest.merge_commit,
                                           manifest.sha256, canonical_digest(record["request"]))
        except (PreregistrationError, ValueError, TypeError, KeyError, OSError):
            # Missing/failed provenance is unknown; callers cannot self-authorize.
            return None
