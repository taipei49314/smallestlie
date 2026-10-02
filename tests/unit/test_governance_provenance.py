"""Synthetic API contracts; no network or real approval is minted by these tests."""

import base64
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from urllib.error import HTTPError

import pytest

from m12_helpers import design
from smallestlie.campaign.preregistration import RunRequest, canonical_digest, digest, prepare_run
from smallestlie.campaign.provenance import (
    GovernanceReference, GovernanceTrustRoot, GitHubGovernanceStore,
    GitHubPreregistrationAuthority, GitHubTransport, HumanMergeApproval,
    ProvenanceError, RepositoryTrust, _NoRedirect,
)


def encoded(value):
    return json.dumps(value, sort_keys=True).encode("utf-8")


class Api:
    def __init__(self):
        self.prs, self.commits, self.trees, self.blobs, self.files = {}, {}, {}, {}, {}
        self.calls = []

    def pull_request(self, repo, number):
        self.calls.append(("pr", repo, number))
        return deepcopy(self.prs[repo, number])

    def pull_files(self, repo, number, page):
        self.calls.append(("files", repo, number, page))
        return deepcopy(self.files.get((repo, number, page), []))

    def git_commit(self, repo, sha):
        self.calls.append(("commit", repo, sha))
        return deepcopy(self.commits[repo, sha])

    def tree(self, repo, sha):
        self.calls.append(("tree", repo, sha))
        return deepcopy(self.trees[repo, sha])

    def blob(self, repo, sha):
        self.calls.append(("blob", repo, sha))
        return deepcopy(self.blobs[repo, sha])

    def add(self, repo, repo_id, number, actor, revision, path, data):
        # Fake commit/tree responses are labelled exact object IDs; blob IDs are real.
        blob_id = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        parts = path.split("/")
        tree_ids = [digest(f"{repo}:{revision}:{index}".encode())[:40] for index in range(len(parts))]
        self.prs[repo, number] = {"number": number, "merged": True, "state": "closed",
            "merged_at": "2026-10-01T00:00:00Z", "merge_commit_sha": revision,
            "merged_by": {"type": "User", "id": actor, "login": "human"},
            "base": {"ref": "main", "repo": {"id": repo_id, "full_name": repo}}}
        self.commits[repo, revision] = {"sha": revision, "tree": {"sha": tree_ids[0]}}
        for index, name in enumerate(parts):
            leaf = index == len(parts) - 1
            self.trees[repo, tree_ids[index]] = {"sha": tree_ids[index], "truncated": False,
                "tree": [{"path": name, "type": "blob" if leaf else "tree",
                          "mode": "100644" if leaf else "040000",
                          "sha": blob_id if leaf else tree_ids[index + 1]}]}
        self.blobs[repo, blob_id] = {"sha": blob_id, "size": len(data), "encoding": "base64",
                                   "content": base64.b64encode(data).decode() + "\n"}
        self.files[repo, number, 1] = [{"filename": path, "status": "added", "sha": blob_id}]
        return blob_id, tree_ids


@pytest.fixture
def setup():
    api = Api()
    root = GovernanceTrustRoot(RepositoryTrust("example/product", 101, "main", frozenset({7})),
                               RepositoryTrust("example/governance", 202, "main", frozenset({8})),
                               (HumanMergeApproval(101, 11, "a" * 40, 7, "synthetic-human-input:phase1"),
                                HumanMergeApproval(202, 22, "c" * 40, 8, "synthetic-human-input:request")))
    manifest = b'{"frozen": "raw bytes"}\r\n'
    request = RunRequest("campaign", "request", "run", "a" * 40, "b" * 40, digest(manifest),
                         "github-pr://example/governance/22/requests/run.json")
    record = {"schema_version": "smallestlie.governance-request/v1", "kind": "formal-run-authorization",
              "request": request.payload(), "phase1": {"pull_request": 11, "manifest_path": "cases/manifest.json"}}
    phase_blob, phase_trees = api.add("example/product", 101, 11, 7, request.phase1_commit,
                                     "cases/manifest.json", manifest)
    auth_blob, auth_trees = api.add("example/governance", 202, 22, 8, "c" * 40,
                                  "requests/run.json", encoded(record))
    store = GitHubGovernanceStore(root, transport=api)
    return api, root, request, record, store, phase_blob, phase_trees, auth_blob, auth_trees


def test_independent_merged_request_and_raw_phase1_manifest(setup):
    api, _, request, _, store, _, _, _, _ = setup
    approval = GitHubPreregistrationAuthority(store).verify(request)
    assert approval is not None
    assert approval.request_sha256 == canonical_digest(request.payload())
    assert approval.reference == request.authorization_ref
    assert approval.phase1_commit == request.phase1_commit
    assert approval.manifest_sha256 == request.manifest_sha256
    assert ("pr", "example/product", 11) in api.calls
    assert ("pr", "example/governance", 22) in api.calls
    blob = store.approved_blob(request.authorization_ref, role="request")
    assert blob.merge_commit == "c" * 40 and blob.merger_id == 8 and blob.repository_id == 202
    assert blob.human_approval_ref == "synthetic-human-input:request"


def test_real_preflight_consumes_authenticated_api_approval(tmp_path, setup):
    api, root, _, _, _, *_ = setup
    request, _ = design(tmp_path)
    request = replace(request, authorization_ref="github-pr://example/governance/23/requests/next.json")
    manifest = (tmp_path / "manifest.json").read_bytes()
    record = {"schema_version": "smallestlie.governance-request/v1", "kind": "formal-run-authorization",
              "request": request.payload(), "phase1": {"pull_request": 12, "manifest_path": "manifest.json"}}
    api.add("example/product", 101, 12, 7, request.phase1_commit, "manifest.json", manifest)
    api.add("example/governance", 202, 23, 8, "f" * 40, "requests/next.json", encoded(record))
    root = replace(root, human_approvals=(
        HumanMergeApproval(101, 12, request.phase1_commit, 7, "synthetic-human-input:phase1-next"),
        HumanMergeApproval(202, 23, "f" * 40, 8, "synthetic-human-input:request-next")))
    authority = GitHubPreregistrationAuthority(GitHubGovernanceStore(root, transport=api))
    plan = prepare_run(tmp_path, "manifest.json", request, authority=authority)
    assert plan.request == request
    assert plan.lock()["approval_provider"] == "github-governance/v1"
    assert [case["case_id"] for case in plan.lock()["cases"]] == ["B"]


@pytest.mark.parametrize("change", [
    "unmerged", "open", "wrong_actor", "bot", "actor_bool", "wrong_repo_id", "repo_id_bool",
    "wrong_repo_name", "wrong_branch", "wrong_number", "missing_merge", "missing_date",
])
@pytest.mark.parametrize("side", ["phase1", "request"])
def test_destination_and_human_role_are_authenticated(setup, change, side):
    api, _, request, _, store, *_ = setup
    pr = api.prs[("example/product", 11) if side == "phase1" else ("example/governance", 22)]
    if change == "unmerged": pr["merged"] = False
    elif change == "open": pr["state"] = "open"
    elif change == "wrong_actor": pr["merged_by"]["id"] = 8 if side == "phase1" else 7
    elif change == "bot": pr["merged_by"]["type"] = "Bot"
    elif change == "actor_bool": pr["merged_by"]["id"] = True
    elif change == "wrong_repo_id": pr["base"]["repo"]["id"] = 999
    elif change == "repo_id_bool": pr["base"]["repo"]["id"] = True
    elif change == "wrong_repo_name": pr["base"]["repo"]["full_name"] = "other/product"
    elif change == "wrong_branch": pr["base"]["ref"] = "unapproved"
    elif change == "wrong_number": pr["number"] = 333
    elif change == "missing_merge": pr["merge_commit_sha"] = None
    elif change == "missing_date": pr["merged_at"] = None
    assert GitHubPreregistrationAuthority(store).verify(request) is None


@pytest.mark.parametrize("field,value", [("run_id", "another-run"), ("request_id", "another-request"),
    ("source_commit", "d" * 40), ("campaign_id", "another-campaign"), ("phase1_commit", "d" * 40),
    ("manifest_sha256", "d" * 64), ("authorization_ref", "github-pr://example/product/11/cases/manifest.json")])
def test_approval_cannot_be_borrowed_for_another_request(setup, field, value):
    _, _, request, _, store, *_ = setup
    assert GitHubPreregistrationAuthority(store).verify(replace(request, **{field: value})) is None


@pytest.mark.parametrize("damage", ["commit", "tree", "truncated", "duplicate", "parent_link", "symlink",
    "submodule", "blob_id", "size", "bool_size", "encoding", "base64", "bytes", "missing_path",
    "inherited", "changed_sha", "removed", "duplicate_changed_file"])
def test_immutable_tree_raw_blob_and_changed_file_must_agree(setup, damage):
    api, _, request, _, store, _, _, blob_id, tree_ids = setup
    repo = "example/governance"
    leaf = api.trees[repo, tree_ids[-1]]["tree"][0]
    blob = api.blobs[repo, blob_id]
    files = api.files[repo, 22, 1]
    if damage == "commit": api.commits[repo, "c" * 40]["sha"] = "e" * 40
    elif damage == "tree": api.trees[repo, tree_ids[0]]["sha"] = "e" * 40
    elif damage == "truncated": api.trees[repo, tree_ids[0]]["truncated"] = True
    elif damage == "duplicate": api.trees[repo, tree_ids[0]]["tree"] *= 2
    elif damage == "parent_link": api.trees[repo, tree_ids[0]]["tree"][0]["mode"] = "120000"
    elif damage == "symlink": leaf["mode"] = "120000"
    elif damage == "submodule": leaf.update(type="commit", mode="160000")
    elif damage == "blob_id": blob["sha"] = "e" * 40
    elif damage == "size": blob["size"] += 1
    elif damage == "bool_size": blob["size"] = True
    elif damage == "encoding": blob["encoding"] = "utf-8"
    elif damage == "base64": blob["content"] += "!"
    elif damage == "bytes": blob["content"] = base64.b64encode(b"different").decode(); blob["size"] = 9
    elif damage == "missing_path": leaf["path"] = "other.json"
    elif damage == "inherited": files.clear()
    elif damage == "changed_sha": files[0]["sha"] = "e" * 40
    elif damage == "removed": files[0]["status"] = "removed"
    elif damage == "duplicate_changed_file": files *= 2
    assert GitHubPreregistrationAuthority(store).verify(request) is None


def test_complete_changed_file_pagination_not_first_page_only(setup):
    api, _, request, _, store, *_ = setup
    original = api.files["example/governance", 22, 1]
    api.files["example/governance", 22, 1] = [{"filename": f"unrelated/{n}"} for n in range(100)]
    api.files["example/governance", 22, 2] = original
    assert GitHubPreregistrationAuthority(store).verify(request) is not None
    assert ("files", "example/governance", 22, 2) in api.calls


def test_incomplete_changed_file_enumeration_is_unknown(setup):
    api, _, request, _, store, *_ = setup
    for page in range(1, 31):
        api.files["example/governance", 22, page] = [
            {"filename": f"unrelated/{page}/{n}"} for n in range(100)]
    assert GitHubPreregistrationAuthority(store).verify(request) is None
    assert ("files", "example/governance", 22, 30) in api.calls
    assert ("files", "example/governance", 22, 31) not in api.calls


def test_api_failure_does_not_fall_back_to_declarations(setup):
    api, _, request, _, store, *_ = setup
    def unavailable(*args):
        raise OSError("API unavailable")
    api.pull_request = unavailable
    assert GitHubPreregistrationAuthority(store).verify(request) is None


@pytest.mark.parametrize("reference", ["main:requests/run.json", "github-pr://example/governance/0/run.json",
    "github-pr://example/governance/22/../run.json", "github-pr://example/governance/22/.git/config",
    "github-pr://example/governance/22/run.json?branch=main", "https://other.example/run.json"])
def test_untrusted_or_mutable_references_are_rejected(reference):
    with pytest.raises(ValueError):
        GovernanceReference.parse(reference)


def test_no_implicit_trust_root_or_other_authority_roles(setup):
    _, root, request, _, store, *_ = setup
    with pytest.raises(ProvenanceError): GitHubGovernanceStore(None)
    with pytest.raises(ProvenanceError): RepositoryTrust("example/product", 101, "main", frozenset())
    with pytest.raises(ProvenanceError): GovernanceTrustRoot(root.product, root.product, root.human_approvals)
    with pytest.raises(ProvenanceError): GovernanceTrustRoot(root.product, root.requests, ())
    with pytest.raises(ProvenanceError): store.approved_blob(request.authorization_ref, role="execution")
    with pytest.raises(ProvenanceError): store.approved_blob(request.authorization_ref, role="review")


@pytest.mark.parametrize("change", ["missing", "commit", "actor"])
def test_user_account_merge_alone_cannot_grant_human_approval(setup, change):
    api, root, request, _, _, *_ = setup
    phase, approved = root.human_approvals
    if change == "missing": approvals = (phase,)
    elif change == "commit": approvals = (phase, replace(approved, merge_commit="e" * 40))
    else:
        # An allowed account can perform an unapproved action with a human PAT.
        root = replace(root, requests=replace(root.requests, merger_ids=frozenset({8, 9})))
        api.prs["example/governance", 22]["merged_by"]["id"] = 9
        approvals = (phase, approved)
    store = GitHubGovernanceStore(replace(root, human_approvals=approvals), transport=api)
    assert GitHubPreregistrationAuthority(store).verify(request) is None


def test_transport_fixed_origin_get_and_raw_json(monkeypatch):
    seen = []
    class Response:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, limit):
            assert limit == 10_000_001
            return b'{"number":22}'
    class Opener:
        def open(self, request, timeout):
            seen.append(request)
            assert timeout == 15
            return Response()
    monkeypatch.setattr("smallestlie.campaign.provenance.build_opener", lambda *args: Opener())
    assert GitHubTransport(token="private-test-token").pull_request("example/governance", 22) == {"number": 22}
    assert seen[0].full_url == "https://api.github.com/repos/example/governance/pulls/22"
    assert seen[0].method == "GET"
    assert seen[0].get_header("Authorization") == "Bearer private-test-token"


def test_transport_redirect_and_http_error_do_not_expose_credentials(monkeypatch):
    class Opener:
        def open(self, request, timeout):
            raise HTTPError(request.full_url, 302, "private-test-token", {}, None)
    def opener(*handlers):
        assert len(handlers) == 1 and isinstance(handlers[0], _NoRedirect)
        assert handlers[0].redirect_request(None, None, 302, "redirect", {}, "https://other.example") is None
        return Opener()
    monkeypatch.setattr("smallestlie.campaign.provenance.build_opener", opener)
    with pytest.raises(ProvenanceError) as exc:
        GitHubTransport(token="private-test-token").pull_request("example/governance", 22)
    assert "private-test-token" not in str(exc.value)


@pytest.mark.parametrize("data", [b"x" * 65, b'{"sha":1,"sha":2}', b"\xff"])
def test_transport_rejects_oversized_ambiguous_and_invalid_text(monkeypatch, data):
    class Response:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, limit):
            assert limit == 65
            return data
    class Opener:
        def open(self, request, timeout): return Response()
    monkeypatch.setattr("smallestlie.campaign.provenance.MAX_BYTES", 64)
    monkeypatch.setattr("smallestlie.campaign.provenance.build_opener", lambda *args: Opener())
    with pytest.raises(ProvenanceError):
        GitHubTransport().pull_request("example/governance", 22)
