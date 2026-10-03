"""Actual single-action producer; local sealing is not immutable publication ACK.

The integration supplies prepared inputs, dispatch and accepted host boundaries.
This module never discovers approvals, grants, repositories or credentials, and
does not publish, continue a campaign or create a trusted completion envelope.
"""

from __future__ import annotations

from dataclasses import dataclass
import importlib.metadata
import os
from pathlib import Path
import platform
import stat
import sys

from smallestlie.attacks.adjudication import sha256, string
from smallestlie.campaign.completion_source import (
    JOURNAL_SCHEMA, PUBLICATION_SCHEMA, SOURCE_SCHEMA, EcLifecycleCompletionAuthority, _prefix, _same,
)
from smallestlie.campaign.evidence_sources import _artifact_path
from smallestlie.campaign.lifecycle import COMPLETION_SCHEMA, _mkdir, _plain_path, _sync_directory, encoded
from smallestlie.campaign.preregistration import PreparedRun, PreregistrationError, canonical_digest, commit, digest, integer, json_mapping
from smallestlie.campaign.provenance import _repository
from smallestlie.ledger.lifecycle import ActionReservation, action_key, action_plan, prerequisites
from smallestlie.sandbox.executor import scrub_environment
from smallestlie.sandbox.windows_capture import capture_windows


class ProducerError(PreregistrationError):
    pass


class _Quota(ProducerError):
    pass


@dataclass(frozen=True)
class ProducerBounds:
    timeout_seconds: int = 30
    max_output_bytes: int = 1_000_000
    max_report_bytes: int = 1_000_000
    max_fixture_bytes: int = 10_000_000
    max_installation_bytes: int = 100_000_000
    cleanup_seconds: int = 5

    def __post_init__(self):
        for name, value in self.__dict__.items():
            integer(value, name, minimum=1)
        if self.max_output_bytes > 10_000_000 or self.max_report_bytes > 10_000_000:
            raise ProducerError("output bounds exceed the raw artifact contract")


@dataclass(frozen=True)
class ProducedAction:
    root: Path
    completion_sha256: str
    publication_sha256: str
    termination_kind: str
    # Deliberately no immutable_ref/accepted/publication ACK field.


def _absolute_plain(path: Path) -> Path:
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ProducerError("absolute path without parent traversal required")
    if any(part.endswith((".", " ")) or ":" in part for part in path.parts[1:]):
        raise ProducerError("ambiguous native path component")
    _plain_path(path)
    # On Windows this also expands existing short-name aliases. Reparse checks
    # must precede resolution, so resolution cannot hide a forbidden link.
    path = path.resolve(strict=False)
    _plain_path(path)
    return path


def _read(path: Path, maximum: int) -> bytes:
    integer(maximum, "file byte bound", minimum=0)
    _plain_path(path)
    with path.open("rb") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            raise ProducerError("producer input is not a regular file")
        data = fh.read(maximum + 1)
    if len(data) > maximum:
        raise _Quota("producer file exceeds its byte budget")
    return data


def measure_tree(root: Path, maximum: int) -> dict[str, str]:
    """Complete regular-file closure, including bytecode; no ignored paths."""
    integer(maximum, "tree byte bound", minimum=1)
    root = _absolute_plain(root)
    if not root.is_dir():
        raise ProducerError("measured tree is missing")
    result, total, aliases = {}, 0, set()
    def failed(error):
        raise error
    for current, directories, files in os.walk(root, followlinks=False, onerror=failed):
        for name in [*directories, *files]:
            _plain_path(Path(current) / name)
        for name in sorted(files):
            path = Path(current) / name
            relative = _artifact_path(path.relative_to(root).as_posix())
            if relative.casefold() in aliases or len(result) >= 20_000:
                raise ProducerError("ambiguous or excessive measured file closure")
            aliases.add(relative.casefold())
            data = _read(path, min(maximum - total, 10_000_000))
            total += len(data)
            if total > maximum:
                raise _Quota("measured tree exceeds its total byte budget")
            result[relative] = digest(data)
    return dict(sorted(result.items()))


def measure_python_installation(bounds: ProducerBounds) -> dict:
    """Actual current CPython and installed pytest; no probes or label copying.

    Hash the full sys.prefix tree and both installed pytest package directories.
    The host must separately admit the interpreter's transitive runtime and
    loader/isolation contract; this does not adopt a runner by itself.
    """
    if platform.python_implementation() != "CPython":
        raise ProducerError("first native producer requires actual CPython")
    executable = _absolute_plain(Path(sys.executable))
    distribution = importlib.metadata.distribution("pytest")
    package_maps = {name: measure_tree(Path(distribution.locate_file(name)), bounds.max_installation_bytes)
                    for name in ("pytest", "_pytest")}
    return {"runtime": {"name": "cpython", "version": platform.python_version(),
                        "artifact_sha256": digest(_read(executable, 10_000_000))},
            "runner": {"name": "pytest", "version": distribution.version,
                       "artifact_sha256": canonical_digest(package_maps)},
            "installed_sha256": canonical_digest(measure_tree(Path(sys.prefix), bounds.max_installation_bytes))}


def _write(path: Path, data: bytes):
    if type(data) is not bytes or len(data) > 10_000_000:
        raise ProducerError("bounded original bytes required")
    _plain_path(path)
    _mkdir(path.parent, exist_ok=True)
    with path.open("xb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    _sync_directory(path.parent)
    if _read(path, 10_000_000) != data:
        raise ProducerError("producer durable raw readback mismatch")


def _collector(prepared):
    package = _absolute_plain(Path(__file__)).parents[1]
    actual = {}
    for path in package.rglob("*.py"):
        logical = "src/smallestlie/" + path.relative_to(package).as_posix()
        actual[logical] = digest(_read(path, 10_000_000))
    frozen = {path: digest(raw) for path, raw in prepared.assets
              if path.startswith("src/smallestlie/") and path.endswith(".py")}
    _same(actual, frozen, "actual producer source closure differs from frozen contracts")
    path = "src/smallestlie/campaign/native_producer.py"
    return path, digest(_read(Path(__file__), 10_000_000))


def _variant(prepared, ticket):
    manifest = json_mapping(prepared.manifest_bytes, "frozen producer manifest")
    declarations = [row for row in manifest["cases"] if row["case_id"] == ticket.case_id]
    if len(declarations) != 1:
        raise ProducerError("ambiguous frozen variant")
    prefix = declarations[0]["variants"][ticket.arm]["root"] + "/"
    files = {path[len(prefix):]: data for path, data in prepared.assets if path.startswith(prefix)}
    for path in files:
        _artifact_path(path)
    _same({path: digest(data) for path, data in files.items()},
          prepared.binding(ticket.case_id)["arms"][ticket.arm]["files"], "frozen producer variant mismatch")
    return files


def _previous(prepared, ticket, states, authorities):
    required = prerequisites(ticket.case_id, ticket.kind, ticket.arm)
    if type(authorities) is not dict or set(authorities) != set(required):
        raise ProducerError("exact independently configured prerequisite sources required")
    for key in required:
        source, state = authorities[key], states["action_states"].get(key)
        if type(source) is not EcLifecycleCompletionAuthority or state is None or state["disposition"] is None:
            raise ProducerError("terminal materialization source missing")
        prior = ActionReservation(**state["reservation"])
        disposition = state["disposition"]
        raw_sha = disposition["completion"]["sha256"]
        # Call the configured provider implementation, never a caller verify hook.
        fact = EcLifecycleCompletionAuthority.verify(source, prepared, prior, raw_sha)
        if (fact is None or fact.termination_kind != "completed" or fact.exit_code != 0
                or not fact.output_complete or not fact.descendants_reaped
                or fact.immutable_ref != disposition["provenance_ref"]):
            raise ProducerError("materialization publication has no independent completed ACK")


def _python_command(prepared, ticket, workspace, bounds):
    profile, binding = prepared.profile(ticket.case_id), prepared.binding(ticket.case_id)
    actual = measure_python_installation(bounds)
    for name in ("runtime", "runner"):
        _same(actual[name], profile[name], "actual installed " + name + " differs from frozen profile")
    _same(actual["installed_sha256"], profile["dependencies"]["installed_sha256"], "installed closure differs from frozen profile")
    command = profile["arms"][ticket.arm]
    argv = tuple(arg.replace("${WORKSPACE}", str(workspace)).replace("${RUNTIME}", sys.executable)
                 for arg in command["argv"])
    if argv[:5] != (sys.executable, "-I", "-B", "-m", "pytest"):
        raise ProducerError("first native producer supports only current isolated CPython -B -m pytest")
    cwd = _absolute_plain(workspace if command["cwd"] == "." else workspace / command["cwd"])
    report_args = []
    for index, arg in enumerate(argv):
        if arg == "--junitxml" and index + 1 < len(argv):
            report_args.append(argv[index + 1])
        elif arg.startswith("--junitxml="):
            report_args.append(arg.split("=", 1)[1])
    if profile["report_format"] != "junit" or len(report_args) != 1:
        raise ProducerError("exact explicit pytest JUnit destination required")
    report_path = Path(report_args[0])
    if report_path.drive and not report_path.is_absolute():
        raise ProducerError("drive-relative report destination forbidden")
    report_path = _absolute_plain(report_path if report_path.is_absolute() else cwd / report_path)
    if not report_path.is_relative_to(workspace) or report_path.exists():
        raise ProducerError("report must be newly produced inside the fixture workspace")
    semantic = profile["semantic_env"]
    if len({key.upper() for key in semantic}) != len(semantic):
        raise ProducerError("case-aliased semantic environment")
    combined = {key.upper(): value for key, value in os.environ.items()}
    combined.update({key.upper(): value for key, value in semantic.items()})
    env = scrub_environment(combined, extra_allow={key.upper() for key in semantic})
    if any(env.get(key.upper()) != value for key, value in semantic.items()):
        raise ProducerError("frozen semantic environment cannot survive credential scrubbing")
    measured = {"runner": actual["runner"], "runtime": actual["runtime"],
        "dependencies": {**profile["dependencies"], "installed_sha256": actual["installed_sha256"],
                         "lock_sha256": digest(prepared.asset(profile["dependencies"]["lock_path"]))},
        "semantic_env": {key: env[key.upper()] for key in semantic}, "workspace_root": str(workspace),
        "runtime_path": sys.executable, "argv": list(argv), "cwd": str(cwd),
        "config": {path: digest(_read(workspace / path, bounds.max_fixture_bytes)) for path in command["config_paths"]}}
    _same(measured["config"], binding["arms"][ticket.arm]["config"], "actual config differs from frozen profile")
    return measured, argv, cwd, env, report_path, actual


def produce_action(prepared: PreparedRun, ticket: ActionReservation, prefix: bytes, *,
                   root: Path, workspace: Path, claims_root: Path, dispatch: dict,
                   epoch: str, action_id: str, first_sequence: int,
                   prerequisite_authorities: dict | None = None,
                   bounds: ProducerBounds = ProducerBounds()) -> ProducedAction:
    """Produce one runner materialization or one CPython/pytest command bundle.

    This is a library receiver for an independently admitted coordinator. Its
    local fsync/readback is not host power-loss acceptance or immutable Git ACK.
    A command reacquires every prior materialization source before any launch.
    """
    if type(prepared) is not PreparedRun or type(ticket) is not ActionReservation or type(bounds) is not ProducerBounds:
        raise ProducerError("exact prepared inputs, reservation and bounds required")
    if ticket.kind not in {"runner_materialize", "runner_command"}:
        raise ProducerError("first native producer does not execute verifier actions")
    integer(first_sequence, "first native journal sequence", minimum=1)
    string(epoch, "external journal epoch")
    string(action_id, "external action identity")
    context = action_plan(prepared)[action_key(ticket.case_id, ticket.kind, ticket.arm)]
    states = _prefix(prefix, prepared, ticket, None)  # Future publication commit is not yet known.
    _previous(prepared, ticket, states, prerequisite_authorities or {})
    collector_path, collector_sha = _collector(prepared)
    profile = prepared.profile(ticket.case_id)
    if (profile["collector_path"], profile["collector_sha256"]) != (collector_path, collector_sha):
        raise ProducerError("frozen collector must be the actual producer")
    expected_dispatch = {"repository", "repository_id", "workflow_id", "workflow_sha256", "collector_sha256",
        "source_commit", "ec_source_commit", "request_sha256", "lock_digest", "run_id", "attempt", "job_id", "host", "generation"}
    if type(dispatch) is not dict or set(dispatch) != expected_dispatch:
        raise ProducerError("exact independently supplied dispatch binding required")
    dispatch = json_mapping(encoded(dispatch), "captured producer dispatch")
    for key in ("request_sha256", "lock_digest", "workflow_sha256", "collector_sha256"):
        sha256(dispatch[key], key)
    for key in ("source_commit", "ec_source_commit"):
        commit(dispatch[key], key)
    for key in ("repository_id", "workflow_id", "run_id", "attempt", "job_id"):
        integer(dispatch[key], key, minimum=1)
    for key in ("repository", "host", "generation"):
        string(dispatch[key], key)
    _repository(dispatch["repository"])
    _same({key: dispatch[key] for key in ("request_sha256", "lock_digest", "source_commit", "collector_sha256")},
          {"request_sha256": canonical_digest(prepared.request.payload()), "lock_digest": ticket.lock_digest,
           "source_commit": prepared.request.source_commit, "collector_sha256": collector_sha}, "producer dispatch binding mismatch")
    # Capture inputs once; caller mutation cannot change the subsequently sealed dispatch.
    root, workspace, claims_root = (_absolute_plain(Path(path)) for path in (root, workspace, claims_root))
    if any(a.is_relative_to(b) for a in (root, workspace, claims_root) for b in (root, workspace, claims_root) if a != b) or len({root, workspace, claims_root}) != 3:
        raise ProducerError("producer, fixture and one-use journal roots must be separate")
    if root.exists() or (ticket.kind.endswith("materialize") and workspace.exists()):
        raise ProducerError("fresh action root and materialization workspace required")
    variant = _variant(prepared, ticket)
    measured, invocation = None, None
    if ticket.kind == "runner_command":
        _same(measure_tree(workspace, bounds.max_fixture_bytes), context["files"][ticket.arm], "actual command fixture differs from frozen files")
        invocation = _python_command(prepared, ticket, workspace, bounds)
        measured = invocation[0]
    _mkdir(claims_root, exist_ok=True)
    reservation_sha = canonical_digest(ticket.to_dict())
    claim = encoded({"request_sha256": dispatch["request_sha256"], "reservation": ticket.to_dict(),
                     "prefix_sha256": digest(prefix), "root": str(root), "epoch": epoch, "action_id": action_id})
    # Both one-use identities remain consumed if a later step fails or the process crashes.
    _write(claims_root / reservation_sha, claim)
    _write(claims_root / canonical_digest({"epoch": epoch, "action_id": action_id}), claim)
    _mkdir(root, exist_ok=False)
    action = root / "action"
    _write(action / "prefix.jsonl", prefix)
    events = []
    def event(name, values):
        row = {"event": name, "seq": first_sequence + len(events), "facts_sha256": canonical_digest(values)}
        log = action / "native-events.jsonl"
        mode = "xb" if not events else "ab"
        _plain_path(log)
        with log.open(mode) as fh:
            fh.write(encoded(row) + b"\n")
            fh.flush()
            os.fsync(fh.fileno())
        events.append(row)
        if _read(log, 10_000_000) != b"".join(encoded(item) + b"\n" for item in events):
            raise ProducerError("native journal append/readback mismatch")
        _sync_directory(action)
    event("ticket_durable_ack", {"prefix_sha256": digest(prefix), "reservation": ticket.to_dict()})
    facts = {"schema_version": SOURCE_SCHEMA, "dispatch": dispatch, "reservation": ticket.to_dict(),
        "context_sha256": ticket.context_sha256, "prefix": {"path": "action/prefix.jsonl", "sha256": digest(prefix)},
        "journal": None, "files": {}, "command": measured, "termination_kind": "internal_error", "exit_code": None,
        "output_complete": False, "descendants_reaped": False, "outputs": {}}
    native = {"schema_version": "smallestlie.native-producer-diagnostics/v1",
              "scope": "local bundle; not immutable publication ACK or host isolation/storage admission"}
    if ticket.kind == "runner_materialize":
        event("work_started", {"context_sha256": ticket.context_sha256, "files": context["files"], "command": None})
        try:
            if sum(map(len, variant.values())) > bounds.max_fixture_bytes:
                raise _Quota("frozen fixture exceeds materialization budget")
            _mkdir(workspace, exist_ok=False)
            for path, data in variant.items():
                _write(workspace / path, data)
            facts["files"] = {ticket.arm: measure_tree(workspace, bounds.max_fixture_bytes)}
            _same(facts["files"], context["files"], "materialized raw files differ from frozen context")
            facts.update(termination_kind="completed", exit_code=0, output_complete=True, descendants_reaped=True)
        except (OSError, ValueError) as exc:
            facts["termination_kind"] = "quota" if isinstance(exc, _Quota) else "internal_error"
            facts["descendants_reaped"] = True  # This branch starts no subprocess.
            native["diagnostic"] = type(exc).__name__
            if workspace.exists():
                try:
                    facts["files"] = {ticket.arm: measure_tree(workspace, bounds.max_fixture_bytes)}
                except (OSError, ValueError):
                    pass
            # v1's work_started event commits the same file map as final facts.
            # A partial copy cannot meet that contract. Preserve its native
            # observations, consume the ticket, and leave the completion absent.
            # Do not rewrite a frozen intention into an alleged measurement.
            event("termination_observed", {key: facts[key] for key in ("termination_kind", "exit_code")})
            event("writer_disposition", {"descendants_reaped": True})
            native.update(termination_kind=facts["termination_kind"], exit_code=None,
                          output_complete=False, descendants_reaped=True,
                          measured_partial_files=facts["files"])
            _write(action / "diagnostics.json", encoded(native))
            raise ProducerError("materialization incomplete; raw diagnostics retained, no completion sealed") from exc
    else:
        facts["files"] = {ticket.arm: measure_tree(workspace, bounds.max_fixture_bytes)}
        _same(facts["files"], context["files"], "command fixture changed before launch release")
        event("work_started", {key: facts[key] for key in ("context_sha256", "files", "command")})
        _, argv, cwd, env, report_path, before_installation = invocation
        captured = capture_windows(argv, cwd, env=env, timeout_seconds=bounds.timeout_seconds,
                                   max_output_bytes=bounds.max_output_bytes, cleanup_seconds=bounds.cleanup_seconds)
        native["capture"] = captured.metadata()
        facts.update(termination_kind=captured.termination_kind, exit_code=captured.exit_code,
                     output_complete=captured.output_complete, descendants_reaped=captured.descendants_reaped)
        outputs = {"stdout": captured.stdout, "stderr": captured.stderr, "report": None}
        try:
            outputs["report"] = _read(report_path, bounds.max_report_bytes)
            _same(measure_python_installation(bounds), before_installation, "installed runtime changed during action")
            # Frozen inputs must still have their original bytes after all writers end.
            _same({path: digest(_read(workspace / path, bounds.max_fixture_bytes)) for path in variant},
                  context["files"][ticket.arm], "frozen command inputs changed during action")
        except (OSError, ValueError) as exc:
            facts["output_complete"] = False
            if facts["termination_kind"] == "completed":
                facts["termination_kind"] = "quota" if isinstance(exc, _Quota) else "output_incomplete"
            native["diagnostic"] = type(exc).__name__
        for role, raw in outputs.items():
            ref = None
            if raw is not None:
                path = f"action/{role}.raw"
                _write(root / path, raw)
                ref = {"path": path, "sha256": digest(raw)}
            facts["outputs"][role] = ref
    event("termination_observed", {key: facts[key] for key in ("termination_kind", "exit_code")})
    event("writer_disposition", {"descendants_reaped": facts["descendants_reaped"]})
    event("outputs_sealed", {key: facts[key] for key in ("output_complete", "outputs")})
    journal = {"schema_version": JOURNAL_SCHEMA, "dispatch": dispatch, "epoch": epoch, "action_id": action_id,
        "reservation_sha256": reservation_sha, "prefix_sha256": digest(prefix),
        "context_sha256": ticket.context_sha256, "events": events}
    journal_bytes = encoded(journal)
    _write(action / "journal.json", journal_bytes)
    facts["journal"] = {"path": "action/journal.json", "sha256": digest(journal_bytes)}
    facts_bytes = encoded(facts)
    _write(action / "facts.json", facts_bytes)
    closure = ["action/prefix.jsonl", "action/journal.json", "action/facts.json"]
    closure.extend(ref["path"] for ref in facts["outputs"].values() if ref is not None)
    publication_bytes = encoded({"schema_version": PUBLICATION_SCHEMA, "dispatch": dispatch,
        "reservation_sha256": reservation_sha, "files": [
            {"path": path, "bytes": len(raw), "sha256": digest(raw)} for path, raw in
            ((path, _read(root / path, 10_000_000)) for path in sorted(closure))]})
    _write(action / "publication.json", publication_bytes)
    wrapper = {"schema_version": COMPLETION_SCHEMA, "binding": context["binding"], "reservation": ticket.to_dict(),
        "context_sha256": ticket.context_sha256, **{key: facts[key] for key in
        ("files", "termination_kind", "exit_code", "output_complete", "descendants_reaped")},
        "outputs": {key: ref["sha256"] if ref is not None else None for key, ref in facts["outputs"].items()},
        "publication_sha256": digest(publication_bytes), "supervisor_sha256": digest(facts_bytes)}
    completion_bytes = encoded(wrapper)
    _write(action / "completion.json", completion_bytes)
    _write(action / "diagnostics.json", encoded(native))
    return ProducedAction(root, digest(completion_bytes), digest(publication_bytes), facts["termination_kind"])
