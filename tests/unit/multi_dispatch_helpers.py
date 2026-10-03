"""Synthetic original-object builders, never cached accepted observations."""

from copy import deepcopy
from dataclasses import replace
import json

import pytest

from m12_helpers import INDEX
from test_mapped_observations import plan, report_state
from test_multi_dispatch_sources import (
    assemble, drop_source, ec_context, make_map, make_multi_map, multi_map_templates, rewrite_ledger,
)
from smallestlie.adjudication.multi_dispatch_reviews import SCHEMA, multi_dispatch_review_context
from smallestlie.adjudication.reviews import frozen_spec
from smallestlie.campaign.lifecycle import ArtifactStore, CaseInputs, encoded
from smallestlie.campaign.multi_dispatch_observations import read_multi_dispatch_observations
from smallestlie.campaign.multi_dispatch_review_source import (
    GitHubMultiDispatchReviewAuthority, MultiDispatchPostRunReviewGrant,
)
from smallestlie.campaign.preregistration import canonical_digest, case_binding, digest
from smallestlie.campaign.provenance import (
    GitHubGovernanceStore, GovernanceTrustRoot, HumanMergeApproval, RepositoryTrust,
)


def native_paths(child):
    facts, files = child["facts"], child["files"]
    for role, ref in facts["outputs"].items():
        if ref is not None:
            data = files.pop(ref["path"])
            path = f"action/{role}.raw"
            files[path] = data
            ref.update(path=path, sha256=digest(data))


@pytest.fixture(scope="module")
def native_templates():
    return {}


@pytest.fixture
def native_multi(make_multi_map, native_templates, plan):
    def make(*, auxiliary=False, selected=None, incomplete=None, native_change=None, auxiliary_change=None):
        reusable = selected is None and incomplete is None and native_change is None and auxiliary_change is None
        key = (canonical_digest(plan.request.payload()), plan.profile("D")["report_format"], auxiliary)
        if reusable and key in native_templates:
            return deepcopy(native_templates[key])
        children = {}

        def native(child):
            native_paths(child)
            if native_change:
                native_change(child)
            ticket = child["ticket"]
            children[ticket.case_id, ticket.kind, ticket.arm] = child

        def inputs_change(inputs):
            for frozen in plan.lock()["cases"]:
                cid = frozen["case_id"]
                arms, artifacts = {}, {}
                for arm in plan.binding(cid)["arms"]:
                    child = children.get((cid, "runner_command", arm))
                    view = arms[arm] = {}
                    if child is None:
                        continue
                    for role, ref in child["facts"]["outputs"].items():
                        if ref is not None:
                            raw, path = child["files"][ref["path"]], f"aux/{arm}/{role}"
                            artifacts[path] = raw
                            view[role] = {"path": path, "sha256": digest(raw)}
                command = children.get((cid, "verifier_command", "attack"))

                def verifier_raw(role):
                    if command is None:
                        return None
                    ref = command["facts"]["outputs"][role]
                    return None if ref is None else command["files"][ref["path"]]

                # This is deliberately not a legacy aggregate runner receipt.
                inputs[cid] = CaseInputs(encoded({"fixture_aux_only": True, "arms": arms}), artifacts,
                    verifier_raw("metadata"), verifier_raw("stdout"), verifier_raw("stderr"))
            if auxiliary_change:
                auxiliary_change(inputs)

        ctx = make_multi_map(selected=selected, incomplete=incomplete, mutate_native=native,
            semantic=auxiliary, mutate_inputs=inputs_change if auxiliary else None)
        if reusable:
            native_templates[key] = deepcopy(ctx)
            return deepcopy(native_templates[key])
        return ctx
    return make


def read(ctx):
    return read_multi_dispatch_observations(ctx["plan"], authority=ctx["authority"])


def case(snapshot, cid="D"):
    assert snapshot is not None
    return next(item for item in snapshot.cases if item.case_id == cid)


def change_index(ctx, mutation):
    entries = [json.loads(line) for line in ctx["files"]["archive/ledger.jsonl"].splitlines()]
    index = json.loads(ctx["files"]["artifacts/" + entries[-1]["payload"]["index"]["sha256"]])
    mutation(index)
    data = encoded(index)
    ctx["files"]["artifacts/" + digest(data)] = data
    rewrite_ledger(ctx, lambda rows: rows[-1]["payload"].update(index=ArtifactStore.reference(data)))


def approve_reviews(ctx, *, mutate=None, review_commit=None):
    prepared, snapshot = ctx["plan"], read(ctx)
    assert snapshot is not None
    index = json.loads(prepared.asset(INDEX))
    source, repo = index["sources"][0], RepositoryTrust("example/reviews", 303, "main", frozenset({9}))
    reviews, grants, approvals = {}, [], []
    for cid, number, revision in (("D", 88, "c" * 40), ("C", 89, "7" * 40)):
        if cid == "D" and review_commit is not None:
            revision = review_commit
        binding = prepared.binding(cid)
        before, after = binding["arms"]["baseline"]["files"], binding["arms"]["attack"]["files"]
        twin = frozen_spec(prepared, cid)["adjudication"]["twin"]
        raw = {"schema_version": SCHEMA, "binding": case_binding(prepared.lock(), cid),
            "engine": prepared.lock()["engine"], "residual_index_sha256": prepared.lock()["residual_index_sha256"],
            "context": multi_dispatch_review_context(prepared, cid, snapshot),
            "source_reviews": [{"source_id": item["id"], "sha256": item["sha256"],
                "rationale": "Synthetic complete-source assessment."} for item in index["sources"]],
            "citations": [{"source_id": source["id"], "start_line": 1, "end_line": 1,
                "quote_sha256": digest(prepared.asset(source["path"]).splitlines(keepends=True)[0])}],
            "theater": {"status": "confirmed", "rationale": "Synthetic effective cheating shape.",
                "changed_paths": sorted(path for path in before.keys() | after.keys() if before.get(path) != after.get(path))},
            "scope": {"status": "in_scope", "rationale": "Synthetic reviewed scope."},
            "residual": {"status": "no_match_reviewed", "row_refs": [], "row_reviews": [],
                "rationale": "Synthetic complete-document residual decision."},
            "twin": {"status": "confirmed", "rationale": "Synthetic same bug and effective cheating near shape.",
                "contrast_sha256": digest(twin["contrast"].encode()), "finding_fingerprints": ["blocking"]} if twin else None}
        if mutate:
            mutate(cid, raw)
        data, path = encoded(raw), f"multi-dispatch/{cid}.json"
        ctx["api"].add(repo.full_name, 303, number, 9, revision, path, data)
        reviews[cid] = data
        grants.append(MultiDispatchPostRunReviewGrant(f"github-pr://{repo.full_name}/{number}/{path}",
            canonical_digest(prepared.request.payload()), prepared.lock()["lock_digest"], cid, digest(data),
            snapshot.validation_sha256, canonical_digest(raw["context"]), f"synthetic-multi-dispatch-semantic:{cid}"))
        approvals.append(HumanMergeApproval(303, number, revision, 9, f"synthetic-multi-dispatch-human:{cid}"))
    root = GovernanceTrustRoot(RepositoryTrust("example/product", 101, "main", frozenset({7})),
        RepositoryTrust("example/requests", 404, "main", frozenset({8})), tuple(approvals), reviews=repo)
    store = GitHubGovernanceStore(root, transport=ctx["api"])
    return {"ctx": ctx, "snapshot": snapshot, "reviews": reviews, "grants": tuple(grants), "store": store,
            "review_authority": GitHubMultiDispatchReviewAuthority(store, grants=tuple(grants))}
