"""W3 single-action receiver proposal. NOT_RUN: source review only.

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
import re
import stat
import sys

from smallestlie.attacks.adjudication import sha256, string
from smallestlie.campaign.completion_source import (
    JOURNAL_SCHEMA, PUBLICATION_SCHEMA, SOURCE_SCHEMA, EcLifecycleCompletionAuthority, _prefix, _same,
)
from smallestlie.campaign.evidence_sources import EcReceiptStore, EcReceiptTrustRoot, EcPublicationGrant, _artifact_path
from smallestlie.adapters.checkwash import CheckwashAdapter
from smallestlie.campaign.lifecycle import COMPLETION_SCHEMA, _mkdir, _plain_path, _sync_directory, encoded
from smallestlie.campaign.preregistration import PreparedRun, PreregistrationError, canonical_digest, case_binding, commit, digest, integer, json_mapping
from smallestlie.campaign import preregistration as preregistration_module
from smallestlie.campaign.provenance import _repository
from smallestlie.ledger.lifecycle import ActionReservation, action_key, action_plan, prerequisites
from smallestlie.sandbox.executor import ExecutionResult, scrub_environment
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


@dataclass(frozen=True)
class InstallationInputs:
    """Admitted restored roots and repository-relative frozen original map assets.

    These parameters supply locations, never an acceptance fact or intended hash.
    Python execution uses this receiver's current actual sys.prefix interpreter.
    Node uses a separate sealed runtime and a precise logical JS-image container.
    """
    contract_root: Path
    python_map_path: str | None = None
    node_root: Path | None = None
    resolver_root: Path | None = None
    node_map_path: str | None = None
    js_map_path: str | None = None
    node_version_stdout_path: str | None = None


@dataclass(frozen=True)
class VerifierInputs:
    baseline_workspace: Path
    attack_workspace: Path
    git_executable: Path
    engine_path: Path
    # Frozen literal environment values; no approval/pin/installed-hash claims.
    contract_path: str


COLLECTOR_PREFIX = "campaigns/checkwash-wave-3/contracts"
COLLECTOR_PATH = COLLECTOR_PREFIX + "/w3_external_collector.py"


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


def _collector(prepared, inputs):
    package = _absolute_plain(Path(preregistration_module.__file__)).parents[1]
    contracts = _absolute_plain(inputs.contract_root)
    source = _absolute_plain(Path(__file__))
    if source != contracts / "w3_external_collector.py":
        raise ProducerError("receiver must execute at its actual frozen collector path")
    for prefix, directory in (("src/smallestlie", package), (COLLECTOR_PREFIX, contracts)):
        actual = {prefix + "/" + path: sha for path, sha in _image_tree(directory,
                  maximum=100_000_000, file_maximum=10_000_000, file_count=20_000).items()}
        frozen = {path: digest(raw) for path, raw in prepared.assets if path.startswith(prefix + "/")}
        if not frozen:
            raise ProducerError("complete collector/source contract assets required")
        _same(actual, frozen, "actual complete source closure differs from frozen contracts")
    return COLLECTOR_PATH, digest(_read(source, 10_000_000))


def _expected_map(prepared, path):
    _artifact_path(path)
    result = json_mapping(prepared.asset(path), "frozen original installation map")
    if not result:
        raise ProducerError("empty original installation map")
    aliases = set()
    for key, value in result.items():
        _installation_path(key)
        sha256(value, "original file digest")
        if key.casefold() in aliases:
            raise ProducerError("ambiguous original installation map")
        aliases.add(key.casefold())
    return result


def _installation_path(value):
    """Confined physical image key, including legitimate scoped npm packages.

    Receipt artifact paths retain their stricter shared grammar. Physical
    installation files may contain '@' or interior spaces, but cannot alias
    another Windows path or escape the explicitly admitted image root.
    """
    if (type(value) is not str or not value or value.startswith("/")
            or any(ord(char) < 32 or char in '\\:<>"|?*' for char in value)):
        raise ProducerError("invalid confined installation path")
    for part in value.split("/"):
        device = part.split(".", 1)[0].upper()
        if (part in {"", ".", ".."} or part.casefold() == ".git"
                or part.endswith((".", " ")) or device in {"CON", "PRN", "AUX", "NUL"}
                or re.fullmatch(r"(?:COM|LPT)[1-9¹²³]", device)):
            raise ProducerError("ambiguous or unconfined installation path")
    return value


def _image_tree(root, *, maximum, file_maximum=256 * 1024 * 1024,
                file_count=50_000, fixture=None, git_admin=False):
    """Complete physical image closure or exactly one admitted logical projection.

    Exclusions are only the fixed resolver fixture child or, for a verifier
    worktree, its required plain .git directory. No expected-path filter exists.
    """
    root = _absolute_plain(root)
    if not root.is_dir():
        raise ProducerError("actual restored installation missing")
    if fixture is not None and (fixture != root / "fixture" or fixture.name != "fixture"):
        raise ProducerError("only the exact resolver fixture child may be projected separately")
    result, aliases, total, observed_dirs = {}, set(), 0, set()
    def failed(error):
        raise error
    for current, directories, files in os.walk(root, followlinks=False, onerror=failed):
        for name in [*directories, *files]:
            _plain_path(Path(current) / name)
        if fixture is not None and Path(current) == root and "fixture" in directories:
            directories.remove("fixture")
        if git_admin and Path(current) == root:
            if ".git" not in directories or (root / ".git").is_file():
                raise ProducerError("fresh regular Git administrative directory required")
            directories.remove(".git")
        for name in directories:
            observed_dirs.add((Path(current) / name).relative_to(root).as_posix())
        for name in sorted(files):
            path = Path(current) / name
            key = _installation_path(path.relative_to(root).as_posix())
            if key.casefold() in aliases or len(result) >= file_count:
                raise ProducerError("ambiguous or excessive installation closure")
            raw = _read(path, min(file_maximum, maximum - total))
            total += len(raw)
            if total > maximum:
                raise _Quota("installation exceeds total byte bound")
            aliases.add(key.casefold())
            result[key] = digest(raw)
    implied_dirs = {"/".join(path.split("/")[:index]) for path in result
                    for index in range(1, len(path.split("/")))}
    _same(sorted(observed_dirs), sorted(implied_dirs), "empty or unbound installation/source directory")
    return dict(sorted(result.items()))


def _installation(prepared, ticket, workspace, inputs, bounds):
    profile = prepared.profile(ticket.case_id)
    if profile["runner"]["name"] == "pytest":
        expected = _expected_map(prepared, inputs.python_map_path)
        _same(measure_tree(_absolute_plain(Path(sys.prefix)), bounds.max_installation_bytes),
              expected, "actual current Python prefix differs from sealed full map")
        actual = measure_python_installation(bounds)
    elif profile["runner"]["name"] in {"mocha", "vitest"}:
        if any(value is None for value in (inputs.node_root, inputs.resolver_root,
                inputs.node_map_path, inputs.js_map_path, inputs.node_version_stdout_path)):
            raise ProducerError("exact sealed Node/JS locations and original frozen inputs required")
        node = _absolute_plain(inputs.node_root)
        resolver = _absolute_plain(inputs.resolver_root)
        if workspace != resolver / "fixture":
            raise ProducerError("Node fixture must be the sole declared resolver child")
        node_expected = _expected_map(prepared, inputs.node_map_path)
        js_expected = _expected_map(prepared, inputs.js_map_path)
        tops = {path.split("/", 1)[0] for path in js_expected}
        if "fixture" in {name.casefold() for name in tops} or "node_modules" not in tops:
            raise ProducerError("sealed JS image conflicts with fixture namespace")
        _plain_path(resolver)
        observed_tops = {path.name for path in resolver.iterdir()}
        allowed_tops = tops | ({"fixture"} if workspace.exists() else set())
        _same(sorted(observed_tops), sorted(allowed_tops), "extra or missing resolver top-level input")
        _same(_image_tree(node, maximum=256 * 1024 * 1024), node_expected,
              "actual complete Node image differs from sealed map")
        js_actual = _image_tree(resolver, maximum=512 * 1024 * 1024, fixture=workspace)
        _same(js_actual, js_expected, "actual complete logical JS image differs from sealed map")
        runner_name = profile["runner"]["name"]
        runner_root = resolver / "node_modules" / runner_name
        runner_map = _image_tree(runner_root, maximum=512 * 1024 * 1024)
        package = json_mapping(_read(runner_root / "package.json", 10_000_000), "actual runner package")
        if package.get("name") != runner_name:
            raise ProducerError("actual installed runner name mismatch")
        version = string(package.get("version"), "actual runner version")
        # The frozen native --version stdout is original preparation metadata,
        # not a profile label. The current full image, including executable bytes,
        # must equal that same preparation image before this value is used.
        version_raw = prepared.asset(inputs.node_version_stdout_path)
        if version_raw not in {b"v24.19.0\n", b"v24.19.0\r\n"}:
            raise ProducerError("unsupported original Node native identity metadata")
        actual = {"runtime": {"name": "node", "version": "24.19.0",
                    "artifact_sha256": digest(_read(node / "node.exe", 256 * 1024 * 1024))},
                  "runner": {"name": runner_name, "version": version,
                    "artifact_sha256": canonical_digest(runner_map)},
                  "installed_sha256": canonical_digest(js_actual)}
    else:
        raise ProducerError("unsupported W3 runner")
    for name in ("runtime", "runner"):
        _same(actual[name], profile[name], "actual runtime/runner differs from frozen profile")
    _same(actual["installed_sha256"], profile["dependencies"]["installed_sha256"],
          "actual installed closure differs from frozen profile")
    return actual


def _runner_command(prepared, ticket, workspace, inputs, bounds):
    before = _installation(prepared, ticket, workspace, inputs, bounds)
    if before["runner"]["name"] == "pytest":
        invocation = _python_command(prepared, ticket, workspace, bounds)
        _same(invocation[5], before, "Python changed during command preflight")
        return invocation
    profile, binding = prepared.profile(ticket.case_id), prepared.binding(ticket.case_id)
    command = profile["arms"][ticket.arm]
    runtime = _absolute_plain(inputs.node_root / "node.exe")
    argv = tuple(arg.replace("${WORKSPACE}", str(workspace)).replace("${RUNTIME}", str(runtime))
                 for arg in command["argv"])
    runner = before["runner"]["name"]
    if runner == "mocha":
        expected_argv = (str(runtime), "../node_modules/mocha/bin/mocha.js", "--no-config", "--no-package",
            "--timeout", "5000", "--reporter", "json", "--reporter-option",
            "output=" + str(workspace) + "/native-report.json", "test/billing.js", "test/other.js")
        report_path = workspace / "native-report.json"
        report_format = "mocha-json"
    else:
        expected_argv = (str(runtime), "../node_modules/vitest/vitest.mjs", "run", "billing.test.js",
            "--config", "vitest.config.mjs", "--configLoader", "native")
        report_path = workspace / "native-report.xml"
        report_format = "vitest-junit"
        if "vitest.config.mjs" not in command["config_paths"]:
            raise ProducerError("Vitest native-loader config must be a frozen input")
    if argv != expected_argv or command["cwd"] != "." or profile["report_format"] != report_format:
        raise ProducerError("unsupported bounded W3 Node command/report contract")
    report_path = _absolute_plain(report_path)
    if not report_path.is_relative_to(workspace) or report_path.exists():
        raise ProducerError("report must be newly produced inside its exact fixture")
    semantic = profile["semantic_env"]
    if (len({key.upper() for key in semantic}) != len(semantic)
            or {key.upper() for key in semantic} & {"NODE_OPTIONS", "NODE_PATH"}):
        raise ProducerError("ambiguous or resolver-altering semantic environment")
    combined = {key.upper(): value for key, value in os.environ.items()}
    combined.update({key.upper(): value for key, value in semantic.items()})
    combined.pop("NODE_OPTIONS", None)
    combined.pop("NODE_PATH", None)
    env = scrub_environment(combined, extra_allow={key.upper() for key in semantic})
    if any(env.get(key.upper()) != value for key, value in semantic.items()):
        raise ProducerError("frozen semantic environment cannot survive scrubbing")
    measured = {"runner": before["runner"], "runtime": before["runtime"],
        "dependencies": {**profile["dependencies"], "installed_sha256": before["installed_sha256"],
                         "lock_sha256": digest(prepared.asset(profile["dependencies"]["lock_path"]))},
        "semantic_env": {key: env[key.upper()] for key in semantic}, "workspace_root": str(workspace),
        "runtime_path": str(runtime), "argv": list(argv), "cwd": str(workspace),
        "config": {path: digest(_read(workspace / path, bounds.max_fixture_bytes)) for path in command["config_paths"]}}
    _same(measured["config"], binding["arms"][ticket.arm]["config"], "actual Node config differs from frozen profile")
    return measured, argv, workspace, env, report_path, before


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


def _previous(prepared, ticket, states, authorities, expected_workspaces):
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
        old = source.store
        if (type(old) is not EcReceiptStore or type(old.root) is not EcReceiptTrustRoot
                or len(old.root.publications) != 1
                or any(type(item) is not EcPublicationGrant for item in old.root.publications)
                or len(source.actions) != 1):
            raise ProducerError("one original terminal store/action source required")
        # Fresh class instances: never invoke carrier store.read, _action or verify hooks.
        fresh = EcLifecycleCompletionAuthority(EcReceiptStore(old.root, transport=old.transport),
                                               source.admission, source.actions)
        fact = EcLifecycleCompletionAuthority.verify(fresh, prepared, prior, raw_sha)
        if (fact is None or fact.termination_kind != "completed" or fact.exit_code != 0
                or not fact.output_complete or not fact.descendants_reaped
                or fact.immutable_ref != disposition["provenance_ref"]):
            raise ProducerError("materialization publication has no independent completed ACK")
        # The original outer EC inventory also authenticates diagnostics. Bind
        # the actual materialization location to this prior exact source, rather
        # than accepting byte-identical runner workspaces as verifier inputs.
        receipt = EcReceiptStore.read(fresh.store, prepared)
        completion_path = fresh.actions[0].completion_path
        diagnostic_path = completion_path.rsplit("/", 1)[0] + "/diagnostics.json"
        original = json_mapping(receipt.artifact(diagnostic_path), "original materialization diagnostics")
        location = _absolute_plain(Path(string(original.get("workspace_root"), "materialized workspace")))
        if location != expected_workspaces[key]:
            raise ProducerError("requested workspace is not the independently ACKed materialization location")


VERIFIER_ENV = {
    "PYTHONUTF8": "1", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
    "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_SYSTEM": "NUL", "GIT_CONFIG_GLOBAL": "NUL",
    "GIT_CONFIG_COUNT": "0", "GIT_ATTR_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0",
    "GIT_AUTHOR_NAME": "Smallestlie W3", "GIT_AUTHOR_EMAIL": "w3@smallestlie.invalid",
    "GIT_COMMITTER_NAME": "Smallestlie W3", "GIT_COMMITTER_EMAIL": "w3@smallestlie.invalid",
    "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+0000",
    "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+0000",
}


def _verifier_runtime(prepared, installation, bounds):
    """The private receiver Python is fixed for every kind of action."""
    expected = _expected_map(prepared, installation.python_map_path)
    prefix = _absolute_plain(Path(sys.prefix))
    executable = _absolute_plain(Path(sys.executable))
    if executable != prefix / "python.exe" or _absolute_plain(Path(sys.base_prefix)) != prefix:
        raise ProducerError("receiver must use the restored private Python executable and prefix")
    if not sys.flags.isolated or not sys.flags.no_user_site or not sys.dont_write_bytecode:
        raise ProducerError("receiver requires isolated no-user-site -I -B startup")
    actual = measure_tree(prefix, bounds.max_installation_bytes)
    _same(actual, expected, "actual verifier Python prefix differs from sealed map")
    if platform.python_implementation() != "CPython" or platform.python_version() != "3.12.10":
        raise ProducerError("actual admitted verifier CPython3.12.10 required")
    return {"name": "cpython", "version": platform.python_version(),
            "artifact_sha256": digest(_read(executable, 10_000_000))}


def _verifier_inputs(prepared, inputs, installation, bounds):
    if type(inputs) is not VerifierInputs:
        raise ProducerError("exact verifier materialization/Git/engine input locations required")
    inputs = VerifierInputs(*(_absolute_plain(Path(path)) for path in
        (inputs.baseline_workspace, inputs.attack_workspace, inputs.git_executable, inputs.engine_path)),
        contract_path=inputs.contract_path)
    contract = json_mapping(prepared.asset(inputs.contract_path), "frozen verifier execution contract")
    if set(contract) != {"semantic_env"}:
        raise ProducerError("verifier contract must supply only its frozen literal semantic environment")
    _same(contract["semantic_env"], VERIFIER_ENV, "unsupported verifier semantic environment")
    runtime = _verifier_runtime(prepared, installation, bounds)
    engine_sha = digest(_read(inputs.engine_path, 10_000_000))
    if engine_sha != prepared.lock()["engine"]["artifact_sha256"]:
        raise ProducerError("actual verifier zipapp differs from frozen published pin")
    if inputs.git_executable.name.lower() != "git.exe" or not inputs.git_executable.is_file():
        raise ProducerError("explicit admitted native MinGit git.exe required")
    git_root = inputs.git_executable.parent.parent
    git_map = _image_tree(git_root, maximum=256 * 1024 * 1024)
    system_root = _absolute_plain(Path(os.environ["SYSTEMROOT"]))
    combined = {key.upper(): value for key, value in os.environ.items()
                if not key.upper().startswith(("GIT_", "PYTHON", "PYTEST", "NODE_"))}
    combined.update(VERIFIER_ENV)
    combined["PATH"] = str(inputs.git_executable.parent) + os.pathsep + str(system_root / "System32")
    env = scrub_environment(combined, extra_allow=set(VERIFIER_ENV))
    if any(env.get(key) != value for key, value in VERIFIER_ENV.items()) or env.get("PATH") != combined["PATH"]:
        raise ProducerError("actual verifier environment differs from the frozen/host contract")
    return inputs, runtime, engine_sha, git_root, git_map, env


def _variant_role(prepared, cid, role):
    manifest = json_mapping(prepared.manifest_bytes, "frozen manifest")
    rows = [row for row in manifest["cases"] if row["case_id"] == cid]
    if len(rows) != 1:
        raise ProducerError("ambiguous verifier variant")
    prefix = rows[0]["variants"][role]["root"] + "/"
    raw = {path[len(prefix):]: data for path, data in prepared.assets if path.startswith(prefix)}
    for path in raw:
        _artifact_path(path)
        if path.split("/", 1)[0].casefold() == ".git":
            raise ProducerError("fixture cannot supply Git administrative bytes")
    _same({path: digest(data) for path, data in raw.items()}, prepared.binding(cid)["arms"][role]["files"],
          "actual frozen variant bytes differ from declared binding")
    return raw


def _replace_inputs(workspace, before, after):
    for name in sorted(set(before) - set(after)):
        path = workspace / name
        _plain_path(path)
        path.unlink()
    for name, raw in after.items():
        path = workspace / name
        _plain_path(path)
        if path.exists():
            if not path.is_file():
                raise ProducerError("replacement path is not regular")
            path.unlink()
        _write(path, raw)
    old_dirs = {workspace / "/".join(name.split("/")[:index]) for name in before
                for index in range(1, len(name.split("/")))}
    for directory in sorted(old_dirs, key=lambda path: len(path.parts), reverse=True):
        _plain_path(directory)
        if directory.is_dir() and not any(directory.iterdir()):
            directory.rmdir()


def _git_setup(prepared, ticket, workspace, inputs, runtime, engine_sha, git_root, git_map,
               env, action, bounds, native):
    """Reserved setup after durable ticket ACK; before the engine work_started event.

    Each actual Git child has complete bounded raw capture sidecars. Setup failure
    consumes the ticket and seals no fabricated engine command or completion.
    """
    binding = prepared.binding(ticket.case_id)
    basemap = measure_tree(inputs.baseline_workspace, bounds.max_fixture_bytes)
    attackmap = measure_tree(inputs.attack_workspace, bounds.max_fixture_bytes)
    _same({"baseline": basemap, "attack": attackmap},
          {role: binding["arms"][role]["files"] for role in ("baseline", "attack")},
          "independently ACKed verifier inputs changed")
    base = _variant_role(prepared, ticket.case_id, "baseline")
    attack = _variant_role(prepared, ticket.case_id, "attack")
    if any(path == name or path.startswith(name + "/") for path in set(base) | set(attack)
           for name in (".checkwash", ".greenwash")):
        raise ProducerError("configured Checkwash policy is unsupported")
    _mkdir(workspace, exist_ok=False)
    for name, raw in base.items():
        _write(workspace / name, raw)
    template = action / "empty-git-template"
    _mkdir(template, exist_ok=False)
    native["git_setup"] = []
    opts = ("-c", "core.hooksPath=NUL", "-c", "core.autocrlf=false", "-c", "core.eol=lf",
            "-c", "core.attributesFile=NUL", "-c", "commit.gpgSign=false", "-c", "core.fsmonitor=false",
            "-c", "core.quotePath=false", "-c", "core.symlinks=false")
    def git(*args):
        if len(native["git_setup"]) >= 32:
            raise _Quota("bounded verifier Git child count exceeded")
        _same(_image_tree(git_root, maximum=256 * 1024 * 1024), git_map, "admitted Git image changed")
        argv = (str(inputs.git_executable), *opts, *args)
        captured = capture_windows(argv, workspace, env=env, timeout_seconds=bounds.timeout_seconds,
                                   max_output_bytes=bounds.max_output_bytes, cleanup_seconds=bounds.cleanup_seconds)
        label = "git-" + str(len(native["git_setup"])).zfill(4)
        for role, raw in (("stdout", captured.stdout), ("stderr", captured.stderr)):
            _write(action / (label + "." + role + ".raw"), raw)
        item = captured.metadata()
        item["stdout_path"], item["stderr_path"] = label + ".stdout.raw", label + ".stderr.raw"
        native["git_setup"].append(item)
        _write(action / (label + ".metadata.json"), encoded(item))
        if (captured.termination_kind != "completed" or captured.exit_code != 0
                or not captured.output_complete or not captured.descendants_reaped):
            raise ProducerError("native Git setup child did not complete with full writer closure")
        _same(_image_tree(git_root, maximum=256 * 1024 * 1024), git_map, "admitted Git image changed after child")
        return captured.stdout
    version = git("--version")
    if not re.fullmatch(rb"git version 2\.55\.0(?:\.windows\.\d+)?\r?\n", version):
        raise ProducerError("actual admitted MinGit2.55.0 version mismatch")
    git("init", "--object-format=sha1", "--initial-branch=main", "--template=" + str(template))
    git("add", "--all", "--", ".")
    git("commit", "--allow-empty", "-m", "W3 baseline")
    base_commit = commit(git("rev-parse", "HEAD").decode("ascii").strip(), "actual baseline commit")
    _replace_inputs(workspace, base, attack)
    git("add", "--all", "--", ".")
    git("commit", "--allow-empty", "-m", "W3 attack")
    head_commit = commit(git("rev-parse", "HEAD").decode("ascii").strip(), "actual attack commit")
    if commit(git("rev-parse", "HEAD~1").decode("ascii").strip(), "actual parent") != base_commit:
        raise ProducerError("actual verifier HEAD~1 differs from captured baseline")
    def blobs(revision):
        result = {}
        raw = git("ls-tree", "-r", "-z", "--full-tree", revision)
        if raw and not raw.endswith(b"\0"):
            raise ProducerError("incomplete native Git tree listing")
        for row in raw.split(b"\0")[:-1]:
            header, name_raw = row.split(b"\t", 1)
            mode, kind, oid = header.decode("ascii").split(" ")
            name = _artifact_path(name_raw.decode("utf-8"))
            if mode not in {"100644", "100755"} or kind != "blob" or name in result:
                raise ProducerError("nonregular or duplicate Git blob")
            commit(oid, "actual Git blob identity")
            result[name] = digest(git("cat-file", "blob", oid))
        return result
    maps = {"baseline": blobs(base_commit), "attack": blobs(head_commit)}
    _same(maps, {"baseline": basemap, "attack": attackmap}, "actual complete Git trees differ from frozen inputs")
    _same(_image_tree(workspace, maximum=bounds.max_fixture_bytes, file_maximum=10_000_000,
                      file_count=20_000, git_admin=True), attackmap, "actual Git worktree differs from attack")
    measured = {"runtime": runtime, "engine_sha256": engine_sha, "semantic_env": dict(VERIFIER_ENV),
        "workspace_root": str(workspace), "runtime_path": sys.executable, "engine_path": str(inputs.engine_path),
        "argv": [sys.executable, str(inputs.engine_path), "check", "HEAD~1..HEAD", "--format", "json"],
        "cwd": str(workspace), "logical_cwd": ".", "base_commit": base_commit,
        "head_commit": head_commit, "fail_on": "high"}
    native["git_image_before_sha256"] = canonical_digest(git_map)
    native["git_executable_sha256"] = digest(_read(inputs.git_executable, 256 * 1024 * 1024))
    return measured, maps, git


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
                   installation: InstallationInputs,
                   verifier: VerifierInputs | None = None,
                   prerequisite_authorities: dict | None = None,
                   bounds: ProducerBounds = ProducerBounds()) -> ProducedAction:
    """Produce one of all four reserved lifecycle action kinds at one collector pin.

    This is a library receiver for an independently admitted coordinator. Its
    local fsync/readback is not host power-loss acceptance or immutable Git ACK.
    A command reacquires every prior materialization source before any launch.
    """
    if type(prepared) is not PreparedRun or type(ticket) is not ActionReservation or type(bounds) is not ProducerBounds:
        raise ProducerError("exact prepared inputs, reservation and bounds required")
    if type(installation) is not InstallationInputs:
        raise ProducerError("exact frozen installation input locations required")
    installation = InstallationInputs(
        contract_root=_absolute_plain(installation.contract_root),
        python_map_path=installation.python_map_path,
        node_root=_absolute_plain(installation.node_root) if installation.node_root is not None else None,
        resolver_root=_absolute_plain(installation.resolver_root) if installation.resolver_root is not None else None,
        node_map_path=installation.node_map_path, js_map_path=installation.js_map_path,
        node_version_stdout_path=installation.node_version_stdout_path)
    if ticket.kind not in {"runner_materialize", "runner_command", "verifier_materialize", "verifier_command"}:
        raise ProducerError("unsupported W3 action")
    receiver_runtime = _verifier_runtime(prepared, installation, bounds)
    integer(first_sequence, "first native journal sequence", minimum=1)
    string(epoch, "external journal epoch")
    string(action_id, "external action identity")
    context = action_plan(prepared)[action_key(ticket.case_id, ticket.kind, ticket.arm)]
    states = _prefix(prefix, prepared, ticket, None)  # Future publication commit is not yet known.
    previous_workspaces = {}
    if ticket.kind == "runner_command":
        previous_workspaces[action_key(ticket.case_id, "runner_materialize", ticket.arm)] = _absolute_plain(workspace)
    elif ticket.kind == "verifier_command":
        if type(verifier) is not VerifierInputs:
            raise ProducerError("explicit verifier materialization locations required")
        previous_workspaces = {action_key(ticket.case_id, "verifier_materialize", role): _absolute_plain(path)
            for role, path in (("baseline", verifier.baseline_workspace), ("attack", verifier.attack_workspace))}
    _previous(prepared, ticket, states, prerequisite_authorities or {}, previous_workspaces)
    collector_path, collector_sha = _collector(prepared, installation)
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
    image_roots = [_absolute_plain(Path(sys.prefix)), _absolute_plain(installation.contract_root),
                   _absolute_plain(Path(preregistration_module.__file__)).parents[1]]
    if ticket.kind.startswith("runner") and profile["runner"]["name"] != "pytest":
        if installation.node_root is None or installation.resolver_root is None:
            raise ProducerError("restored Node runtime and resolver roots required")
        image_roots.extend((_absolute_plain(installation.node_root), _absolute_plain(installation.resolver_root)))
    if any(a == b or a.is_relative_to(b) or b.is_relative_to(a)
           for index, a in enumerate(image_roots) for b in image_roots[index + 1:]):
        raise ProducerError("protected runtime, resolver and source roots must be separate")
    if any(a == b or a.is_relative_to(b) or b.is_relative_to(a)
           for a in (root, claims_root) for b in image_roots):
        raise ProducerError("protected source/images must be separate from output and claims")
    for image in image_roots:
        if image == installation.resolver_root and ticket.kind.startswith("runner") and profile["runner"]["name"] != "pytest":
            if workspace != image / "fixture":
                raise ProducerError("wrong resolver workspace")
        elif image == workspace or image.is_relative_to(workspace) or workspace.is_relative_to(image):
            raise ProducerError("fixture must be separate from protected source/runtime images")
    if root.exists() or ((ticket.kind.endswith("materialize") or ticket.kind == "verifier_command") and workspace.exists()):
        raise ProducerError("fresh action root and materialization workspace required")
    variant = _variant(prepared, ticket)
    measured, invocation, verifier_state = None, None, None
    if ticket.kind == "runner_materialize":
        _installation(prepared, ticket, workspace, installation, bounds)
    if ticket.kind == "runner_command":
        _same(measure_tree(workspace, bounds.max_fixture_bytes), context["files"][ticket.arm], "actual command fixture differs from frozen files")
        invocation = _runner_command(prepared, ticket, workspace, installation, bounds)
        measured = invocation[0]
    if ticket.kind == "verifier_command":
        verifier_state = _verifier_inputs(prepared, verifier, installation, bounds)
        selected = verifier_state[0]
        locations = (workspace, selected.baseline_workspace, selected.attack_workspace)
        if any(a == b or a.is_relative_to(b) or b.is_relative_to(a)
               for index, a in enumerate(locations) for b in locations[index + 1:]):
            raise ProducerError("verifier baseline/attack/command workspaces must be independent")
        for location in locations[1:]:
            if any(location == other or location.is_relative_to(other) or other.is_relative_to(location)
                   for other in (root, claims_root, *image_roots, verifier_state[3])):
                raise ProducerError("verifier materializations overlap protected roots")
        for location in (root, claims_root, *locations):
            if (location == selected.engine_path or selected.engine_path.is_relative_to(location)
                    or location == verifier_state[3] or location.is_relative_to(verifier_state[3])
                    or verifier_state[3].is_relative_to(location)):
                raise ProducerError("verifier work/output roots overlap engine or admitted Git image")
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
              "scope": "local bundle; not immutable publication ACK or host isolation/storage admission",
              "workspace_root": str(workspace), "receiver_runtime": receiver_runtime}
    if ticket.kind.endswith("materialize"):
        event("work_started", {"context_sha256": ticket.context_sha256, "files": context["files"], "command": None})
        try:
            if sum(map(len, variant.values())) > bounds.max_fixture_bytes:
                raise _Quota("frozen fixture exceeds materialization budget")
            _mkdir(workspace, exist_ok=False)
            for path, data in variant.items():
                _write(workspace / path, data)
            facts["files"] = {ticket.arm: measure_tree(workspace, bounds.max_fixture_bytes)}
            _same(facts["files"], context["files"], "materialized raw files differ from frozen context")
            _same(_verifier_runtime(prepared, installation, bounds), receiver_runtime,
                  "private receiver Python changed during materialization")
            _same(_collector(prepared, installation), (collector_path, collector_sha),
                  "frozen collector/source changed during materialization")
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
    elif ticket.kind == "runner_command":
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
            _same(_verifier_runtime(prepared, installation, bounds), receiver_runtime,
                  "private receiver Python changed during runner action")
            _same(_installation(prepared, ticket, workspace, installation, bounds), before_installation,
                  "installed runtime changed during action")
            _same(_collector(prepared, installation), (collector_path, collector_sha),
                  "collector source changed during action")
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
    else:
        selected, runtime, engine_sha, git_root, git_map, env = verifier_state
        try:
            measured, maps, git = _git_setup(prepared, ticket, workspace, selected, runtime,
                engine_sha, git_root, git_map, env, action, bounds, native)
            _same(_verifier_runtime(prepared, installation, bounds), runtime,
                  "actual verifier Python changed during reserved Git setup")
            _same(digest(_read(selected.engine_path, 10_000_000)), engine_sha,
                  "actual pinned engine changed before launch")
            _same(_collector(prepared, installation), (collector_path, collector_sha),
                  "actual collector changed before engine launch")
        except (OSError, ValueError, TypeError, UnicodeError, KeyError) as exc:
            native["diagnostic"] = "git_setup_incomplete:" + type(exc).__name__
            _write(action / "diagnostics.json", encoded(native))
            raise ProducerError("reserved Git setup incomplete; no engine completion sealed") from exc
        facts["command"], facts["files"] = measured, maps
        _same(maps, context["files"], "measured verifier input roles differ from context")
        event("work_started", {key: facts[key] for key in ("context_sha256", "files", "command")})
        captured = capture_windows(tuple(measured["argv"]), workspace, env=env,
            timeout_seconds=bounds.timeout_seconds, max_output_bytes=bounds.max_output_bytes,
            cleanup_seconds=bounds.cleanup_seconds)
        native["capture"] = captured.metadata()
        facts.update(termination_kind=captured.termination_kind, exit_code=captured.exit_code,
                     output_complete=captured.output_complete, descendants_reaped=captured.descendants_reaped)
        try:
            _same(_verifier_runtime(prepared, installation, bounds), runtime, "verifier Python changed during action")
            _same(digest(_read(selected.engine_path, 10_000_000)), engine_sha, "actual engine changed during action")
            _same(_image_tree(git_root, maximum=256 * 1024 * 1024), git_map, "actual admitted Git image changed")
            _same(_collector(prepared, installation), (collector_path, collector_sha), "collector/source changed")
            _same(commit(git("rev-parse", "HEAD~1").decode("ascii").strip(), "post engine baseline"),
                  measured["base_commit"], "engine changed baseline commit")
            _same(commit(git("rev-parse", "HEAD").decode("ascii").strip(), "post engine head"),
                  measured["head_commit"], "engine changed attack commit")
            _same(_image_tree(workspace, maximum=bounds.max_fixture_bytes, file_maximum=10_000_000,
                             file_count=20_000, git_admin=True), maps["attack"], "engine changed frozen attack inputs")
            _same(measure_tree(selected.baseline_workspace, bounds.max_fixture_bytes), maps["baseline"],
                  "original baseline materialization changed")
            _same(measure_tree(selected.attack_workspace, bounds.max_fixture_bytes), maps["attack"],
                  "original attack materialization changed")
        except (OSError, ValueError, TypeError, UnicodeError) as exc:
            facts["output_complete"] = False
            if facts["termination_kind"] == "completed":
                facts["termination_kind"] = "quota" if isinstance(exc, _Quota) else "output_incomplete"
            native["diagnostic"] = "post_engine_incomplete:" + type(exc).__name__
        binding = prepared.binding(ticket.case_id)
        metadata = {"schema_version": "smallestlie.verifier-observation/v1",
            "binding": case_binding(prepared.lock(), ticket.case_id), "arm": "attack", "adapter": "checkwash",
            "engine": prepared.lock()["engine"], "baseline_tree_sha256": binding["arms"]["baseline"]["tree_sha256"],
            "attack_tree_sha256": binding["arms"]["attack"]["tree_sha256"], "base_commit": measured["base_commit"],
            "head_commit": measured["head_commit"], "argv": measured["argv"], "cwd": measured["logical_cwd"],
            "fail_on": "high", "termination_kind": facts["termination_kind"], "exit_code": captured.exit_code,
            "truncated": not captured.output_complete, "stdout_sha256": digest(captured.stdout),
            "stderr_sha256": digest(captured.stderr)}
        # Preserve the real adapter normalization separately: canonical metadata
        # has a strict schema and cannot accept TargetVerdict's extra fields.
        native["target_verdict"] = None
        if (captured.exit_code is not None and captured.termination_kind == "completed"
                and captured.output_complete and captured.descendants_reaped):
            try:
                execution = ExecutionResult("run_checkwash_check", list(captured.argv), captured.cwd,
                    captured.exit_code, captured.stdout.decode("utf-8"), captured.stderr.decode("utf-8"),
                    captured.termination_kind == "timeout")
                native["target_verdict"] = CheckwashAdapter().parse_verdict(workspace, execution).to_dict()
            except (ValueError, TypeError, UnicodeError) as exc:
                native["adapter_diagnostic"] = type(exc).__name__
        else:
            native["adapter_diagnostic"] = "native_incomplete_not_verdict"
        outputs = {"metadata": encoded(metadata), "stdout": captured.stdout, "stderr": captured.stderr}
        for role, raw in outputs.items():
            path = "action/" + role + ".raw"
            _write(root / path, raw)
            facts["outputs"][role] = {"path": path, "sha256": digest(raw)}
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
    _write(action / "diagnostics.json", encoded(native))
    wrapper = {"schema_version": COMPLETION_SCHEMA, "binding": context["binding"], "reservation": ticket.to_dict(),
        "context_sha256": ticket.context_sha256, **{key: facts[key] for key in
        ("files", "termination_kind", "exit_code", "output_complete", "descendants_reaped")},
        "outputs": {key: ref["sha256"] if ref is not None else None for key, ref in facts["outputs"].items()},
        "publication_sha256": digest(publication_bytes), "supervisor_sha256": digest(facts_bytes)}
    completion_bytes = encoded(wrapper)
    # Preserve every raw child/diagnostic sidecar. Leave room below the outer
    # EC reader's 256-file/50MB inventory limits for its own native records.
    inventory = measure_tree(root, 40_000_000)
    if len(inventory) + 1 > 192:
        raise _Quota("complete action exceeds the original publication inventory budget")
    total_bytes = sum((root / path).stat().st_size for path in inventory)
    if total_bytes + len(completion_bytes) > 40_000_000:
        raise _Quota("complete action exceeds the original publication byte budget")
    _write(action / "completion.json", completion_bytes)
    return ProducedAction(root, digest(completion_bytes), digest(publication_bytes), facts["termination_kind"])
