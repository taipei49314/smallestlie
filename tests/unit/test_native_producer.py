"""Actual local producer bytes with synthetic external governance/API grants.

The tiny pytest child qualifies the producer. It is not W3, runner adoption,
human preregistration, host acceptance or a live EC publication.
"""

from copy import deepcopy
from dataclasses import replace
import json
import os
from pathlib import Path

import pytest

from m12_helpers import encoded as design_encoded, prepared
from test_evidence_sources import ctx as ec_context, republish
from test_formal_lifecycle import begin
from smallestlie.campaign.completion_source import (
    ADMISSION_SCHEMA, EcLifecycleCompletionAuthority, LifecycleActionGrant, LifecycleCollectorAdmission,
)
from smallestlie.campaign.lifecycle import encoded, validate_completion
from smallestlie.campaign.native_producer import (
    ProducerBounds, ProducerError, _absolute_plain, measure_python_installation, measure_tree, produce_action,
)
from smallestlie.campaign.preregistration import canonical_digest, digest
from smallestlie.ledger.lifecycle import action_key
from smallestlie.sandbox.windows_capture import WindowsCapture

COLLECTOR = "src/smallestlie/campaign/native_producer.py"
BOUNDS = ProducerBounds(timeout_seconds=15, max_installation_bytes=100_000_000)
HONEST = "from pathlib import Path\ndef test_total():\n    assert int(Path('src/billing.py').read_text()) == 2\n"
CHEAT = "import pytest\n" + HONEST.replace("def test_total():", "@pytest.mark.skip(reason='producer qualification')\ndef test_total():")
# Non-Windows runs exercise only the pure contracts and explicit unsupported
# native branch. These markers are never installed-runtime evidence.
UNSUPPORTED_INSTALLATION = {"runtime": {"name": "cpython", "version": "unsupported-host-contract",
    "artifact_sha256": "1" * 64}, "runner": {"name": "pytest", "version": "unsupported-host-contract",
    "artifact_sha256": "2" * 64}, "installed_sha256": "3" * 64}


@pytest.fixture(autouse=True)
def unsupported_host_contract(monkeypatch):
    if os.name != "nt":
        monkeypatch.setattr("smallestlie.campaign.native_producer.measure_python_installation",
                            lambda bounds: deepcopy(UNSUPPORTED_INSTALLATION))


@pytest.fixture(scope="module")
def plan(tmp_path_factory):
    # Measurement runs only when this test is executed on its authorized host.
    actual = measure_python_installation(BOUNDS) if os.name == "nt" else deepcopy(UNSUPPORTED_INSTALLATION)
    def change(manifest, assets):
        profile = json.loads(assets["profiles/runner.json"])
        profile.update(runtime=actual["runtime"], runner=actual["runner"], collector_path=COLLECTOR,
                       collector_sha256=digest(assets[COLLECTOR]), semantic_env={"PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"})
        profile["dependencies"]["installed_sha256"] = actual["installed_sha256"]
        profile["arms"] = {role: {"argv": ["${RUNTIME}", "-I", "-B", "-m", "pytest", "-p", "no:cacheprovider",
                                        "--junitxml=${WORKSPACE}/junit.xml", "tests/test_billing.py"],
                                  "cwd": ".", "config_paths": []}
                           for role in ("baseline", "attack", "repair", "twin")}
        assets["profiles/runner.json"] = design_encoded(profile)
        assets["contracts/collector.py"] = assets[COLLECTOR]
        assets["locks/runner.lock"] = assets["uv.lock"]
        for declaration in manifest["cases"]:
            spec = json.loads(assets[declaration["spec_path"]])
            spec["runner_protocol"]["profile_sha256"] = digest(assets["profiles/runner.json"])
            spec["mutations"][0]["content"] = CHEAT
            assets[declaration["spec_path"]] = design_encoded(spec)
            for role, variant in declaration["variants"].items():
                prefix = variant["root"]
                assets[prefix + "/tests/test_billing.py"] = (HONEST if role in {"baseline", "repair"} else CHEAT).encode()
                assets[prefix + "/src/billing.py"] = b"2\n" if role == "repair" else b"1\n"
    return prepared(tmp_path_factory.mktemp("native-producer-design"), twin=True, change=change)


@pytest.fixture
def context(ec_context):
    ctx = ec_context
    root = replace(ctx["root"], collector_path=COLLECTOR)
    ctx["root"] = root
    ctx["api"].install(root.repository, "e" * 40, {root.workflow_path: b"synthetic external workflow",
        COLLECTOR: ctx["plan"].asset(COLLECTOR)})
    grant = root.publications[0]
    dispatch = {"repository": root.repository, "repository_id": root.repository_id, "workflow_id": root.workflow_id,
        "workflow_sha256": root.workflow_sha256, "collector_sha256": root.collector_sha256,
        "source_commit": grant.source_commit, "ec_source_commit": grant.ec_source_commit,
        "request_sha256": grant.request_sha256, "lock_digest": grant.lock_digest,
        "run_id": grant.run_id, "attempt": grant.attempt, "job_id": grant.job_id,
        "host": root.host, "generation": root.generation}
    contracts = {"collector": "synthetic collector admission", "host_storage": "synthetic host admission",
                 "prelaunch_journal": "synthetic journal admission"}
    raw = encoded({"schema_version": ADMISSION_SCHEMA, "dispatch": dispatch, "contracts": contracts})
    ctx["api"].install(root.repository, "b" * 40, {"admissions/native.json": raw})
    ctx["admission"] = LifecycleCollectorAdmission(grant.request_sha256, grant.lock_digest, grant.source_commit,
        grant.ec_source_commit, grant.run_id, grant.attempt, grant.job_id, root.repository_id, root.workflow_id,
        root.workflow_sha256, root.collector_sha256, root.host, root.generation, "b" * 40,
        "admissions/native.json", digest(raw), contracts["collector"], contracts["host_storage"], contracts["prelaunch_journal"])
    ctx["dispatch"] = dispatch
    return ctx


def bundle(ctx, produced, ticket, *, revision="f" * 40, epoch="native-epoch", identity="materialize", sequence=10):
    """Explicit test grants for exact original producer bytes, with fresh GETs."""
    files = {path.relative_to(produced.root).as_posix(): path.read_bytes()
             for path in produced.root.rglob("*") if path.is_file()}
    files["ec-workload.json"] = ctx["files"]["ec-workload.json"]
    ctx.update(files=files, supervisor=None)
    ctx["root"] = replace(ctx["root"], publications=(replace(ctx["root"].publications[0], receipt_commit=revision),))
    republish(ctx)
    action = LifecycleActionGrant(canonical_digest(ticket.to_dict()), "action/completion.json", produced.completion_sha256,
        "action/facts.json", digest(files["action/facts.json"]), "action/publication.json", produced.publication_sha256,
        epoch, identity, sequence, sequence + 4)
    authority = EcLifecycleCompletionAuthority(ctx["store"], ctx["admission"], (action,))
    return authority, files


def produce(ctx, tmp_path, session, ticket, **kwargs):
    return produce_action(ctx["plan"], ticket, session.ledger.path.read_bytes(), root=tmp_path / "producer",
        workspace=tmp_path / "fixture", claims_root=tmp_path / "claims", dispatch=ctx["dispatch"],
        epoch="native-epoch", action_id="materialize", first_sequence=10, **kwargs)


def complete(session, ticket, authority, files):
    session.completion_authority = authority
    facts = json.loads(files["action/facts.json"])
    return session.complete_action(ticket, files["action/completion.json"], sources={
        "publication": files["action/publication.json"], "supervisor": files["action/facts.json"]},
        outputs={key: files[ref["path"]] if ref is not None else None for key, ref in facts["outputs"].items()})


def test_actual_materialization_requires_independent_publication_to_complete(context, tmp_path):
    session = begin(tmp_path, context["plan"])
    ticket = session.reserve_action("D", kind="runner_materialize", arm="baseline")
    produced = produce(context, tmp_path, session, ticket)
    assert produced.termination_kind == "completed" and not hasattr(produced, "immutable_ref")
    assert (tmp_path / "fixture/tests/test_billing.py").read_bytes() == HONEST.encode()
    local = json.loads((produced.root / "action/completion.json").read_bytes())
    assert local["files"] == {"baseline": measure_tree(tmp_path / "fixture", BOUNDS.max_fixture_bytes)}
    invalid = validate_completion(context["plan"], ticket, encoded(local), sources={
        "publication": (produced.root / "action/publication.json").read_bytes(),
        "supervisor": (produced.root / "action/facts.json").read_bytes()}, outputs={}, authority=None)
    assert not invalid.valid
    authority, files = bundle(context, produced, ticket)
    assert complete(session, ticket, authority, files).valid
    assert ("job", "example/ec", 700) in context["api"].calls


def test_quota_materialization_preserves_failure_without_sealing_completion(context, tmp_path):
    session = begin(tmp_path, context["plan"])
    ticket = session.reserve_action("D", kind="runner_materialize", arm="baseline")
    with pytest.raises(ProducerError, match="incomplete"):
        produce(context, tmp_path, session, ticket, bounds=ProducerBounds(max_fixture_bytes=1))
    root = tmp_path / "producer/action"
    diagnostics = json.loads((root / "diagnostics.json").read_bytes())
    assert diagnostics["termination_kind"] == "quota" and not diagnostics["output_complete"]
    assert not (root / "completion.json").exists() and not (root / "publication.json").exists()
    assert (root / "prefix.jsonl").read_bytes() == session.ledger.path.read_bytes()
    with pytest.raises(FileExistsError):
        produce_action(context["plan"], ticket, session.ledger.path.read_bytes(), root=tmp_path / "retry",
            workspace=tmp_path / "retry-fixture", claims_root=tmp_path / "claims", dispatch=context["dispatch"],
            epoch="other", action_id="other", first_sequence=20)
    assert not (tmp_path / "retry").exists()


@pytest.mark.parametrize("damage", ["bool_job", "bad_sha", "bad_repo", "extra", "wrong_lock", "relative", "overlap", "traversal", "trailing_alias", "ads"])
def test_receiver_rejects_invalid_bindings_and_paths_before_ack(context, tmp_path, damage):
    session = begin(tmp_path, context["plan"])
    ticket = session.reserve_action("D", kind="runner_materialize", arm="baseline")
    dispatch = deepcopy(context["dispatch"])
    root, workspace = tmp_path / "producer", tmp_path / "fixture"
    if damage == "bool_job": dispatch["job_id"] = True
    elif damage == "bad_sha": dispatch["ec_source_commit"] = "bad"
    elif damage == "bad_repo": dispatch["repository"] = "../ec"
    elif damage == "extra": dispatch["accepted"] = True
    elif damage == "wrong_lock": dispatch["lock_digest"] = "0" * 64
    elif damage == "relative": root = Path("relative")
    elif damage == "overlap": workspace = root / "fixture"
    elif damage == "traversal": workspace = tmp_path / "fixture" / ".." / "outside"
    elif damage == "trailing_alias": workspace = tmp_path / "fixture."
    else: workspace = tmp_path / "fixture:stream"
    with pytest.raises(ValueError):
        produce_action(context["plan"], ticket, session.ledger.path.read_bytes(), root=root, workspace=workspace,
            claims_root=tmp_path / "claims", dispatch=dispatch, epoch="epoch", action_id="id", first_sequence=1)
    assert not (tmp_path / "claims").exists() and not (tmp_path / "producer").exists()


def test_duplicate_external_action_identity_consumes_no_second_work(context, tmp_path):
    session = begin(tmp_path, context["plan"])
    first = session.reserve_action("D", kind="runner_materialize", arm="baseline")
    produce(context, tmp_path, session, first)
    second = session.reserve_action("D", kind="runner_materialize", arm="attack")
    with pytest.raises(FileExistsError):
        produce_action(context["plan"], second, session.ledger.path.read_bytes(), root=tmp_path / "second",
            workspace=tmp_path / "second-fixture", claims_root=tmp_path / "claims", dispatch=context["dispatch"],
            epoch="native-epoch", action_id="materialize", first_sequence=20)
    assert not (tmp_path / "second").exists() and not (tmp_path / "second-fixture").exists()


@pytest.mark.parametrize("damage", ["prefix", "collector"])
def test_frozen_prefix_and_actual_source_are_required_before_ack(context, tmp_path, damage):
    session = begin(tmp_path, context["plan"])
    ticket = session.reserve_action("D", kind="runner_materialize", arm="baseline")
    plan, prefix = context["plan"], session.ledger.path.read_bytes()
    if damage == "prefix":
        lines = prefix.splitlines()
        row = json.loads(lines[-1])
        row["entry_digest"] = "0" * 64
        lines[-1] = encoded(row)
        prefix = b"\n".join(lines) + b"\n"
    else:
        plan = replace(plan, assets=tuple((path, raw + b"# changed\n" if path == COLLECTOR else raw)
                                         for path, raw in plan.assets))
    with pytest.raises(ValueError):
        produce_action(plan, ticket, prefix, root=tmp_path / "producer", workspace=tmp_path / "fixture",
            claims_root=tmp_path / "claims", dispatch=context["dispatch"], epoch="epoch", action_id="id", first_sequence=1)
    assert not (tmp_path / "claims").exists() and not (tmp_path / "fixture").exists()


def test_failed_prefix_persistence_never_releases_fixture_and_ticket_stays_consumed(context, tmp_path, monkeypatch):
    import smallestlie.campaign.native_producer as implementation
    session = begin(tmp_path, context["plan"])
    ticket = session.reserve_action("D", kind="runner_materialize", arm="baseline")
    original = implementation._write
    def fail_prefix(path, data):
        if path.name == "prefix.jsonl":
            raise OSError("synthetic storage failure")
        return original(path, data)
    monkeypatch.setattr(implementation, "_write", fail_prefix)
    with pytest.raises(OSError, match="storage failure"):
        produce(context, tmp_path, session, ticket)
    assert not (tmp_path / "fixture").exists()
    assert not (tmp_path / "producer/action/completion.json").exists()
    monkeypatch.setattr(implementation, "_write", original)
    with pytest.raises(FileExistsError):
        produce_action(context["plan"], ticket, session.ledger.path.read_bytes(), root=tmp_path / "retry",
            workspace=tmp_path / "retry-fixture", claims_root=tmp_path / "claims", dispatch=context["dispatch"],
            epoch="fresh-epoch", action_id="fresh-id", first_sequence=20)
    assert not (tmp_path / "retry-fixture").exists()


def command_ready(ctx, tmp_path):
    session = begin(tmp_path, ctx["plan"])
    ticket = session.reserve_action("D", kind="runner_materialize", arm="baseline")
    produced = produce(ctx, tmp_path, session, ticket)
    authority, files = bundle(ctx, produced, ticket)
    assert complete(session, ticket, authority, files).valid
    command = session.reserve_action("D", kind="runner_command", arm="baseline")
    return session, command, authority


@pytest.mark.parametrize("damage", ["missing", "duck_source", "changed_raw", "running_job"])
def test_command_reacquires_exact_terminal_prerequisite_before_launch(context, tmp_path, monkeypatch, damage):
    session, ticket, authority = command_ready(context, tmp_path)
    def forbidden(*args, **kwargs):
        raise AssertionError("unauthorized command was launched")
    monkeypatch.setattr("smallestlie.campaign.native_producer.capture_windows", forbidden)
    sources = {action_key("D", "runner_materialize", "baseline"): authority}
    if damage == "missing": sources = {}
    elif damage == "duck_source": sources = {next(iter(sources)): object()}
    elif damage == "changed_raw":
        context["files"]["action/facts.json"] += b" "
        context["api"].install("example/ec", "f" * 40, context["files"])
    else: context["api"].jobs["example/ec", 700]["status"] = "in_progress"
    with pytest.raises(ProducerError):
        produce_action(context["plan"], ticket, session.ledger.path.read_bytes(), root=tmp_path / "command",
            workspace=tmp_path / "fixture", claims_root=tmp_path / "claims", dispatch=context["dispatch"],
            epoch="native-epoch", action_id="command", first_sequence=20, prerequisite_authorities=sources)
    assert not (tmp_path / "command").exists()


def test_actual_pytest_nonzero_report_is_preserved_as_completed_not_green(context, tmp_path):
    session, ticket, authority = command_ready(context, tmp_path)
    arguments = dict(root=tmp_path / "command", workspace=tmp_path / "fixture", claims_root=tmp_path / "claims",
        dispatch=context["dispatch"], epoch="native-epoch", action_id="command", first_sequence=20,
        prerequisite_authorities={action_key("D", "runner_materialize", "baseline"): authority}, bounds=BOUNDS)
    if os.name != "nt":
        with pytest.raises(OSError, match="unsupported"):
            produce_action(context["plan"], ticket, session.ledger.path.read_bytes(), **arguments)
        return
    produced = produce_action(context["plan"], ticket, session.ledger.path.read_bytes(), **arguments)
    facts = json.loads((produced.root / "action/facts.json").read_bytes())
    assert produced.termination_kind == "completed", facts
    assert facts["exit_code"] == 1 and facts["output_complete"] and facts["descendants_reaped"]
    report = (produced.root / "action/report.raw").read_bytes()
    assert report == (tmp_path / "fixture/junit.xml").read_bytes() and b"<failure" in report
    assert (produced.root / "action/stdout.raw").read_bytes() and facts["command"]["runtime"] == context["plan"].profile("D")["runtime"]
    publication, files = bundle(context, produced, ticket, revision="a" * 40, identity="command", sequence=20)
    assert complete(session, ticket, publication, files).valid


@pytest.mark.parametrize("damage", ["missing_report", "oversized_report", "changed_installation", "changed_input"])
def test_closed_parent_with_incomplete_evidence_cannot_become_completed(context, tmp_path, monkeypatch, damage):
    import smallestlie.campaign.native_producer as implementation
    session, ticket, authority = command_ready(context, tmp_path)
    workspace = tmp_path / "fixture"
    actual_measure = implementation.measure_python_installation
    calls = []
    def measure(bounds):
        result = actual_measure(bounds)
        calls.append(result)
        if damage == "changed_installation" and len(calls) > 1:
            result["installed_sha256"] = "0" * 64
        return result
    def synthetic_capture(argv, cwd, *, env, **kwargs):
        if damage != "missing_report":
            (workspace / "junit.xml").write_bytes(b"x" * 101 if damage == "oversized_report" else b"<testsuite/>")
        if damage == "changed_input":
            (workspace / "src/billing.py").write_bytes(b"2\n")
        return WindowsCapture(argv, str(cwd), canonical_digest(env), "completed", 0,
            b"synthetic captured bytes", b"", 24, 0, True, True, None, None)
    monkeypatch.setattr(implementation, "measure_python_installation", measure)
    monkeypatch.setattr(implementation, "capture_windows", synthetic_capture)
    produced = produce_action(context["plan"], ticket, session.ledger.path.read_bytes(), root=tmp_path / "command",
        workspace=workspace, claims_root=tmp_path / "claims", dispatch=context["dispatch"],
        epoch="native-epoch", action_id="command", first_sequence=20,
        prerequisite_authorities={action_key("D", "runner_materialize", "baseline"): authority},
        bounds=ProducerBounds(max_report_bytes=100))
    facts = json.loads((produced.root / "action/facts.json").read_bytes())
    expected = "quota" if damage == "oversized_report" else "output_incomplete"
    assert produced.termination_kind == expected and facts["exit_code"] == 0
    assert not facts["output_complete"] and facts["descendants_reaped"]
    assert (produced.root / "action/stdout.raw").read_bytes() == b"synthetic captured bytes"
    publication, files = bundle(context, produced, ticket, revision="a" * 40, identity="command", sequence=20)
    result = complete(session, ticket, publication, files)
    assert result.valid and result.status == expected


@pytest.mark.parametrize("path", ["../outside.xml", "sub/../../outside.xml"])
def test_report_parent_traversal_is_rejected_before_native_launch(context, tmp_path, path):
    from smallestlie.campaign.native_producer import _python_command
    session = begin(tmp_path, context["plan"])
    ticket = session.reserve_action("D", kind="runner_materialize", arm="baseline")
    produce(context, tmp_path, session, ticket)
    profile = context["plan"].profile("D")
    profile["arms"]["baseline"]["argv"][-2] = "--junitxml=" + path
    altered = replace(context["plan"], profiles=tuple((cid, design_encoded(profile)) for cid, _ in context["plan"].profiles))
    with pytest.raises(ProducerError, match="traversal"):
        _python_command(altered, replace(ticket, kind="runner_command"), tmp_path / "fixture", BOUNDS)


def test_tree_hash_includes_hidden_and_bytecode_and_enforces_budget(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    (root / ".hidden").write_bytes(b"x")
    (root / "__pycache__").mkdir()
    (root / "__pycache__/module.pyc").write_bytes(b"bytecode")
    assert measure_tree(root, 9) == {".hidden": digest(b"x"), "__pycache__/module.pyc": digest(b"bytecode")}
    with pytest.raises(ProducerError, match="budget"):
        measure_tree(root, 8)
    with pytest.raises(ProducerError, match="traversal"):
        _absolute_plain(root / ".." / "outside")
