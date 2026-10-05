"""Single-action receiver for the independently admitted trusted EC launcher.

Default CLI refuses. Only direct --private-action enters the native one-use
channel; its trusted parent authenticates and holds the exact runtime closure.
NOT_RUN until the exact entry/EC sources are qualified and independently read.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys


HOST = "LAPTOP-50KP71KA"
MANIFEST = "campaigns/checkwash-wave-3/manifest.json"
PHASE1 = "f673f07110ba6e0b592e6e3ee1e69278ba05e731"
MANIFEST_SHA = "daf4497f252e141a5d13e2b1e8d461aa590b8089c3006b69703081b24c37c432"
COLLECTOR = "campaigns/checkwash-wave-3/contracts/w3_external_collector.py"
COLLECTOR_SHA = "ee972284ec1052937afb7ddf078da6e6a28a265e7fec318454ef0cf8eeb0fa29"
MAX_RAW = 10_000_000
MAX_DESIGN = 100_000_000
SCHEMA = "smallestlie.w3-formal-action-input/v1"
INSTALLATION_KEYS = {"contract_root", "python_map_path", "node_root", "resolver_root",
    "node_map_path", "js_map_path", "node_version_stdout_path"}
VERIFIER_KEYS = {"baseline_workspace", "attack_workspace", "git_executable", "engine_path", "contract_path"}
INSTALLATIONS = "campaigns/checkwash-wave-3/installations/"


class Refusal(ValueError):
    pass


class UnsupportedBoundary(Refusal):
    pass


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pairs(items):
    out = {}
    for key, value in items:
        if key in out:
            raise Refusal("duplicate JSON key")
        out[key] = value
    return out


def object_bytes(raw):
    if type(raw) is not bytes or len(raw) > MAX_RAW:
        raise Refusal("bounded original JSON bytes required")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(Refusal("nonfinite JSON")))
    if type(value) is not dict:
        raise Refusal("JSON object required")
    return value


def plain(value):
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise Refusal("explicit absolute nontraversing path required")
    for part in path.parts[1:]:
        if (part.endswith((" ", ".")) or any(ord(char) < 32 or char in ':<>"|?*' for char in part)
                or re.fullmatch(r"(?i)(?:CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\..*)?", part)):
            raise Refusal("ambiguous native path")
    for item in (*reversed(path.parents), path):
        if item.exists() or item.is_symlink():
            info = item.lstat()
            if (stat.S_ISLNK(info.st_mode)
                    or getattr(info, "st_file_attributes", 0) & 0x400
                    or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1)):
                raise Refusal("linked/reparse/hardlinked entry input")
    return path


def relative(value):
    if (type(value) is not str or not value or value.startswith("/")
            or any(ord(char) < 32 or char in '\\:<>"|?*' for char in value)):
        raise Refusal("unsafe repository-relative source name")
    for part in value.split("/"):
        if (part in {"", ".", ".."} or part.endswith((" ", "."))
                or part.casefold() == ".git"
                or re.fullmatch(r"(?i)(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", part)):
            raise Refusal("unsafe source component")
    return value


def exact_mapping(value, names, label):
    if type(value) is not dict or set(value) != names:
        raise Refusal(label + " requires an exact JSON object and field set")
    return value


def text(value, label):
    if (type(value) is not str or not value.strip() or len(value) > 4096
            or any(ord(char) < 32 for char in value)):
        raise Refusal(label + " requires a bounded nonempty literal string")
    return value


def path_text(value, label):
    return plain(text(value, label))


def read(value):
    path = plain(value)
    with path.open("rb") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            raise Refusal("original input must be regular")
        raw = fh.read(MAX_RAW + 1)
    if len(raw) > MAX_RAW:
        raise Refusal("original input exceeds byte bound")
    return raw


def write_new(value, raw):
    if type(raw) is not bytes or len(raw) > MAX_RAW:
        raise Refusal("bounded original output bytes required")
    path = plain(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    plain(path.parent)
    with path.open("xb") as fh:
        fh.write(raw)
        fh.flush()
        os.fsync(fh.fileno())
    if read(path) != raw:
        raise Refusal("exclusive original-byte readback mismatch")
    # No Windows directory-entry power-loss guarantee is asserted here.


@dataclass(frozen=True)
class FreshDesign:
    """Bytes returned by future trusted live channel, never a JSON authority.

    Channel responsibility: fresh native PR/commit/tree/blob authentication,
    source descent, changed manifest at human-approved agent-operated Phase1,
    exact direct-input human approvals and independent formal request original.
    Constructing this byte carrier grants none of those responsibilities.
    """
    manifest: bytes
    assets: tuple[tuple[str, bytes], ...]
    human_input_originals: tuple[bytes, ...]


class MissingECChannels:
    """Design seams, NOT existing framework/EC APIs or runtime fallbacks."""

    def authenticate_before_imports(self, packet):
        raise UnsupportedBoundary("fresh original source/human-request channel not implemented")

    def governance_root(self):
        raise UnsupportedBoundary("independent human-input registry importer not implemented")

    def native_transport(self):
        raise UnsupportedBoundary("fresh GovernanceTransport/ReceiptTransport broker not implemented")

    def session_release(self, packet, prepared, ticket, prefix):
        # Must verify native release/admission and custody of the exact original
        # ledger/workspace/claims paths; return actual dispatch, never ok=True.
        raise UnsupportedBoundary("native session custody/release gate not implemented")

    def prerequisite_sources(self, packet, prepared, ticket):
        # Actual independently imported per-ticket roots/admissions/action grants;
        # fresh EcLifecycleCompletionAuthority instances, never saved proofs.
        raise UnsupportedBoundary("live prerequisite source importer not implemented")

    def launch_private_once(self, argv, env):
        # Accepted kill-on-close native job, finite outer timeout/disk, secretless
        # child, complete raw loader output/writer disposition; no second attempt.
        raise UnsupportedBoundary("admitted whole-job private launcher not implemented")

    def private_environment(self, packet):
        # Rebuild fixed environment, including an admitted MinGit-only/system
        # PATH for prepare_run's read-only Git proofs, disabled global/system
        # configs and hooks. Do not forward ambient credentials or loader flags.
        raise UnsupportedBoundary("admitted fixed private loader environment not implemented")


def open_admitted_ec_channels(packet_raw):
    # These fixed environment locations come from the admitted suspended parent,
    # never the packet. The parent holds noninheritable deny-write/delete handles
    # over every runtime leaf and the directory roots throughout this child.
    root_value = os.environ.pop("EC_W3_RUNTIME_ROOT", None)
    map_value = os.environ.pop("EC_W3_RUNTIME_MAP", None)
    map_sha = os.environ.pop("EC_W3_RUNTIME_MAP_SHA256", None)
    if not root_value or not map_value or not map_sha:
        raise UnsupportedBoundary("trusted EC runtime closure is absent")
    root = plain(root_value).resolve()
    original = read(map_value)
    if sha(original) != map_sha:
        raise Refusal("trusted runtime original map differs")
    expected = object_bytes(original)
    if not expected or len(expected) > 256:
        raise Refusal("bounded complete EC runtime map required")
    actual, total = {}, 0
    def failed(error):
        raise error
    for here, dirs, files in os.walk(root, followlinks=False, onerror=failed):
        for name in (*dirs, *files):
            plain(Path(here) / name)
        for name in files:
            file = Path(here) / name
            rel = relative(file.relative_to(root).as_posix())
            raw = read(file)
            total += len(raw)
            if len(actual) >= 256 or total > 10_000_000:
                raise Refusal("EC runtime closure quota")
            actual[rel] = sha(raw)
    if actual != expected or any(name.casefold() != "w3_runtime" for name in {p.split("/")[0] for p in expected}):
        raise Refusal("complete actual trusted EC runtime closure differs")
    if any(name == "w3_runtime" or name.startswith("w3_runtime.") for name in sys.modules):
        raise Refusal("runtime imported before closure authentication")
    sys.path.insert(0, str(root))
    from w3_runtime.channels import open_private
    return open_private(packet_raw, design_type=FreshDesign)


def packet_bytes(raw):
    packet = object_bytes(raw)
    expected = {"schema_version", "request", "source_root", "private_python_root",
        "lock_path", "ticket_path", "prefix_path", "installation", "verifier",
        "workspace_root", "claims_root", "epoch", "action_id", "first_sequence",
        "channel_handle", "custody_handle", "release_ref"}
    exact_mapping(packet, expected, "action packet")
    if packet["schema_version"] != SCHEMA:
        raise Refusal("exact proposed single-action input shape required")
    request = packet["request"]
    if (type(request) is not dict or set(request) != {"campaign_id", "request_id", "run_id",
            "phase1_commit", "source_commit", "manifest_sha256", "authorization_ref"}
            or request["phase1_commit"] != PHASE1 or request["manifest_sha256"] != MANIFEST_SHA
            or request["campaign_id"] != "checkwash-wave-3"
            or request["source_commit"] != os.environ.get("EC_WORKLOAD_SHA")):
        raise Refusal("single action must bind actual approved Phase1 and exact executable source")
    for name, value in request.items():
        text(value, "request." + name)
    if not re.fullmatch(r"[0-9a-f]{40}", request["source_commit"]):
        raise Refusal("exact source SHA required")
    for name in ("source_root", "private_python_root", "lock_path", "ticket_path",
                 "prefix_path", "workspace_root", "claims_root"):
        path_text(packet[name], name)
    installation = exact_mapping(packet["installation"], INSTALLATION_KEYS, "installation")
    path_text(installation["contract_root"], "installation.contract_root")
    relative(text(installation["python_map_path"], "installation.python_map_path"))
    for name in ("node_root", "resolver_root"):
        if installation[name] is not None:
            path_text(installation[name], "installation." + name)
    for name in ("node_map_path", "js_map_path", "node_version_stdout_path"):
        if installation[name] is not None:
            relative(text(installation[name], "installation." + name))
    if packet["verifier"] is not None:
        verifier = exact_mapping(packet["verifier"], VERIFIER_KEYS, "verifier")
        for name in VERIFIER_KEYS - {"contract_path"}:
            path_text(verifier[name], "verifier." + name)
        relative(text(verifier["contract_path"], "verifier.contract_path"))
    for name in ("epoch", "action_id", "channel_handle", "custody_handle", "release_ref"):
        if type(packet[name]) is not str or not packet[name] or len(packet[name]) > 1024:
            raise Refusal("bounded explicit action/channel identity required")
    if type(packet["first_sequence"]) is not int or packet["first_sequence"] < 1:
        raise Refusal("positive native journal interval start required")
    return packet


def authenticate_local_source(packet, originals):
    if type(originals) is not FreshDesign or not originals.human_input_originals:
        raise Refusal("fresh trusted native originals required before product imports")
    source = plain(packet["source_root"]).resolve()
    if sha(originals.manifest) != MANIFEST_SHA or read(source / MANIFEST) != originals.manifest:
        raise Refusal("actual manifest differs from fresh approved original")
    manifest = object_bytes(originals.manifest)
    assets = dict(originals.assets)
    if len(assets) != len(originals.assets) or set(assets) != set(manifest["assets"]):
        raise Refusal("fresh original assets omit/add/duplicate frozen entries")
    total, aliases = 0, set()
    for name, raw in assets.items():
        relative(name)
        if name.casefold() in aliases or type(raw) is not bytes:
            raise Refusal("aliased/nonraw frozen source")
        aliases.add(name.casefold())
        total += len(raw)
        if len(raw) > MAX_RAW or total > MAX_DESIGN:
            raise Refusal("frozen source byte quota")
        record = manifest["assets"][name]
        blob = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
        if (sha(raw) != record["sha256"] or blob != record["git_blob"]
                or read(source / name) != raw):
            raise Refusal("actual frozen source differs from authenticated raw Git bytes")
    for root_name in manifest["closed_roots"]:
        relative(root_name)
        root = plain(source / root_name)
        if not root.is_dir():
            raise Refusal("frozen closed root is missing")
        observed, dirs = set(), {root_name}
        def failed(exc):
            raise exc
        for here, children, files in os.walk(root, followlinks=False, onerror=failed):
            for name in (*children, *files):
                child = plain(Path(here) / name)
                if child.is_dir():
                    dirs.add(child.relative_to(source).as_posix())
                elif not child.is_file():
                    raise Refusal("nonregular closed source")
            observed.update((Path(here) / name).relative_to(source).as_posix() for name in files)
        wanted = {name for name in assets if name.startswith(root_name + "/")}
        wanted_dirs = {"/".join(name.split("/")[:i]) for name in wanted
            for i in range(len(root_name.split("/")), len(name.split("/")))}
        if not wanted or observed != wanted or dirs != wanted_dirs:
            raise Refusal("complete local closed roots differ from frozen original")
    # Adding only frozen src must not shadow dependencies with an unlisted yaml.py.
    if {path.name for path in (source / "src").iterdir()} != {"smallestlie"}:
        raise Refusal("unexpected source import parent")
    if sha(assets[COLLECTOR]) != COLLECTOR_SHA:
        raise Refusal("actual unified receiver bytes differ")
    return source


def authenticate_private_prefix(packet, originals):
    private = plain(packet["private_python_root"]).resolve()
    path = "campaigns/checkwash-wave-3/installations/python-files.json"
    expected = object_bytes(dict(originals.assets)[path])
    actual, aliases, total = {}, set(), 0
    def failed(exc):
        raise exc
    for here, directories, files in os.walk(private, followlinks=False, onerror=failed):
        for name in (*directories, *files):
            plain(Path(here) / name)
        for name in files:
            item = Path(here) / name
            key = relative(item.relative_to(private).as_posix())
            if key.casefold() in aliases or len(actual) >= 20_000:
                raise Refusal("ambiguous/excessive private prefix closure")
            aliases.add(key.casefold())
            raw = read(item)
            total += len(raw)
            if total > 100_000_000:
                raise Refusal("private prefix total byte quota")
            actual[key] = sha(raw)
    if not actual or actual != expected:
        raise Refusal("actual private prefix differs from authenticated full original map")
    return private


def validate_ticket(prepared, raw):
    from smallestlie.campaign.preregistration import PreparedRun, canonical_digest
    from smallestlie.ledger.lifecycle import ActionReservation, KINDS, PROTOCOL, action_key, action_plan
    if type(prepared) is not PreparedRun:
        raise Refusal("exact actual PreparedRun required")
    value = exact_mapping(object_bytes(raw), {item.name for item in fields(ActionReservation)}, "original ticket")
    for name in ("protocol", "case_id", "kind", "arm"):
        text(value[name], "ticket." + name)
    for name in ("binding_sha256", "context_sha256", "lock_digest", "entry_digest"):
        if type(value[name]) is not str or not re.fullmatch(r"[0-9a-f]{64}", value[name]):
            raise Refusal("ticket requires exact SHA-256 identities")
    if type(value["seq"]) is not int or value["seq"] < 1:
        raise Refusal("ticket sequence requires an exact positive integer")
    if value["protocol"] != PROTOCOL or value["kind"] not in KINDS or value["arm"] not in {"baseline", "attack", "twin", "repair"}:
        raise Refusal("unsupported actual lifecycle ticket role")
    ticket = ActionReservation(**value)
    plan = action_plan(prepared)
    key = action_key(ticket.case_id, ticket.kind, ticket.arm)
    if key not in plan:
        raise Refusal("ticket does not name a frozen action slot")
    context = plan[key]
    if (ticket.lock_digest != prepared.lock()["lock_digest"]
            or ticket.binding_sha256 != canonical_digest(context["binding"])
            or ticket.context_sha256 != canonical_digest(context)):
        raise Refusal("ticket differs from actual prepared lock/binding/context")
    return ticket


def frozen_map(prepared, name):
    raw = prepared.asset(relative(text(name, "frozen map reference")))
    result = object_bytes(raw)
    if not result:
        raise Refusal("frozen installation map must be nonempty")
    aliases = set()
    for path, value in result.items():
        relative(path)
        if path.casefold() in aliases or type(value) is not str or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise Refusal("ambiguous or invalid frozen installation map")
        aliases.add(path.casefold())
    return result


def receiver_inputs(packet, prepared, ticket, collector, source, out):
    """Early syntax/reference/path checks; never session custody or admission."""
    from smallestlie.campaign.preregistration import canonical_digest
    installation = exact_mapping(packet["installation"], {item.name for item in fields(collector.InstallationInputs)}, "installation")
    values = {name: value for name, value in installation.items()}
    for name in ("contract_root", "node_root", "resolver_root"):
        if values[name] is not None:
            values[name] = path_text(values[name], "installation." + name).resolve()
    if values["contract_root"] != source / "campaigns/checkwash-wave-3/contracts":
        raise Refusal("collector contracts must be the authenticated actual frozen source")
    if values["python_map_path"] != INSTALLATIONS + "python-files.json":
        raise Refusal("receiver requires the actual frozen Python map reference")
    python_map = frozen_map(prepared, values["python_map_path"])
    profile, binding = prepared.profile(ticket.case_id), prepared.binding(ticket.case_id)
    needs_node = ticket.kind.startswith("runner") and profile["runner"]["name"] in {"mocha", "vitest"}
    node_fields = {"node_root", "resolver_root", "node_map_path", "js_map_path", "node_version_stdout_path"}
    if needs_node:
        if any(values[name] is None for name in node_fields):
            raise Refusal("Node runner requires every actual image/map/version location")
        for name, suffix in (("node_map_path", "node-files.json"), ("js_map_path", "js-files.json"),
                             ("node_version_stdout_path", "node-version.stdout")):
            if values[name] != INSTALLATIONS + suffix:
                raise Refusal("Node input must reference its actual frozen original")
        frozen_map(prepared, values["node_map_path"])
        js_map = frozen_map(prepared, values["js_map_path"])
        if canonical_digest(js_map) != profile["dependencies"]["installed_sha256"]:
            raise Refusal("frozen JS map differs from the selected profile")
        if prepared.asset(values["node_version_stdout_path"]) not in {b"v24.19.0\n", b"v24.19.0\r\n"}:
            raise Refusal("frozen Node native version metadata differs")
        if path_text(packet["workspace_root"], "workspace").resolve() != values["resolver_root"] / "fixture":
            raise Refusal("Node workspace must be the exact single resolver fixture child")
    elif any(values[name] is not None for name in node_fields):
        raise Refusal("this action cannot supply unused Node image locations")
    if ticket.kind.startswith("runner") and profile["runner"]["name"] == "pytest":
        if canonical_digest(python_map) != profile["dependencies"]["installed_sha256"]:
            raise Refusal("frozen Python map differs from the selected profile")
    lock_path = relative(text(profile["dependencies"]["lock_path"], "dependency lock reference"))
    if sha(prepared.asset(lock_path)) != binding["dependency_lock_sha256"]:
        raise Refusal("frozen dependency lock reference differs")
    manifest = object_bytes(prepared.manifest_bytes)
    rows = [row for row in manifest["cases"] if row["case_id"] == ticket.case_id]
    if len(rows) != 1:
        raise Refusal("ambiguous selected frozen case")
    row = rows[0]
    for arm, arm_binding in binding["arms"].items():
        config = profile["arms"][arm]["config_paths"]
        if type(config) is not list:
            raise Refusal("frozen config references require an exact list")
        root = relative(row["variants"][arm]["root"])
        observed = {relative(text(name, "config reference")): sha(prepared.asset(root + "/" + relative(name))) for name in config}
        if observed != arm_binding["config"]:
            raise Refusal("frozen config references differ from the actual arm binding")
    installed = collector.InstallationInputs(**values)
    verifier = None
    if ticket.kind == "verifier_command":
        raw = exact_mapping(packet["verifier"], {item.name for item in fields(collector.VerifierInputs)}, "verifier")
        selected = {name: value for name, value in raw.items()}
        for name in VERIFIER_KEYS - {"contract_path"}:
            selected[name] = path_text(selected[name], "verifier." + name).resolve()
        contract_path = relative(text(selected["contract_path"], "verifier contract"))
        if contract_path != "campaigns/checkwash-wave-3/contracts/verifier-environment.json" or contract_path not in manifest["contract_paths"]:
            raise Refusal("actual frozen verifier contract reference required")
        contract = exact_mapping(object_bytes(prepared.asset(contract_path)), {"semantic_env"}, "verifier contract")
        if type(contract["semantic_env"]) is not dict or contract["semantic_env"] != collector.VERIFIER_ENV:
            raise Refusal("frozen verifier semantic environment differs")
        if sha(read(selected["engine_path"])) != prepared.lock()["engine"]["artifact_sha256"]:
            raise Refusal("actual verifier engine bytes differ from the frozen pin")
        if selected["git_executable"].name.lower() != "git.exe" or not selected["git_executable"].is_file():
            raise Refusal("explicit regular native Git location required")
        verifier = collector.VerifierInputs(**selected)
        locations = [path_text(packet["workspace_root"], "workspace").resolve(),
                     verifier.baseline_workspace, verifier.attack_workspace]
        if any(a == b or a.is_relative_to(b) or b.is_relative_to(a)
               for index, a in enumerate(locations) for b in locations[index + 1:]):
            raise Refusal("verifier command/baseline/attack locations overlap")
        if not verifier.baseline_workspace.is_dir() or not verifier.attack_workspace.is_dir():
            raise Refusal("verifier materialization locations are missing")
    elif packet["verifier"] is not None:
        raise Refusal("verifier inputs apply only to verifier_command")
    workspace, claims = (path_text(packet[name], name).resolve() for name in ("workspace_root", "claims_root"))
    private = path_text(packet["private_python_root"], "private prefix").resolve()
    out = plain(out).resolve()
    protected = [source, private]
    if needs_node:
        protected.extend((installed.node_root, installed.resolver_root))
    if any(a == b or a.is_relative_to(b) or b.is_relative_to(a)
           for index, a in enumerate(protected) for b in protected[index + 1:]):
        raise Refusal("authenticated source/private/Node image roots overlap")
    if any(a == b or a.is_relative_to(b) or b.is_relative_to(a)
           for a in (out, claims) for b in protected):
        raise Refusal("entry output/claims overlap authenticated source or protected images")
    if out == claims or out.is_relative_to(claims) or claims.is_relative_to(out):
        raise Refusal("entry output and persistent claims overlap")
    if any(workspace == other or workspace.is_relative_to(other) or other.is_relative_to(workspace)
           for other in (source, private, out, claims)):
        raise Refusal("workspace overlaps source/private/output/claims")
    if needs_node and (workspace == installed.node_root or workspace.is_relative_to(installed.node_root)
                       or installed.node_root.is_relative_to(workspace)):
        raise Refusal("Node workspace overlaps the runtime image")
    if verifier is not None:
        for location in (verifier.baseline_workspace, verifier.attack_workspace):
            if any(location == other or location.is_relative_to(other) or other.is_relative_to(location)
                   for other in (source, private, out, claims)):
                raise Refusal("verifier materialization overlaps protected roots")
    if (out / "entry-inputs").exists() or (out / "receiver").exists():
        raise Refusal("fresh exclusive entry input/bundle output required")
    if (ticket.kind.endswith("materialize") or ticket.kind == "verifier_command") and workspace.exists():
        raise Refusal("this reserved action requires a new workspace")
    if ticket.kind == "runner_command" and not workspace.is_dir():
        raise Refusal("runner command materialization location is missing")
    return installed, verifier


def run_private(packet, packet_raw, channels, out):
    # Preserve the actual bytes supplied by main, never a JSON reserialization.
    if packet_bytes(packet_raw) != packet:
        raise Refusal("parsed packet differs from the original input bytes")
    originals = channels.authenticate_before_imports(packet)  # Fresh/native, not an offline bundle.
    source = authenticate_local_source(packet, originals)
    private = authenticate_private_prefix(packet, originals)
    if (not sys.flags.isolated or not sys.flags.no_user_site or not sys.dont_write_bytecode
            or Path(sys.prefix).resolve() != private or Path(sys.base_prefix).resolve() != private
            or Path(sys.executable).resolve() != private / "python.exe"):
        raise Refusal("sealed private -I -B receiver required")
    if any(name == "smallestlie" or name.startswith("smallestlie.") for name in sys.modules):
        raise Refusal("product was imported before fresh source authentication")
    sys.path.insert(0, str(source / "src"))
    from smallestlie.campaign.preregistration import RunRequest, prepare_run
    from smallestlie.campaign.provenance import (
        GovernanceTrustRoot, GitHubGovernanceStore, GitHubPreregistrationAuthority,
    )
    root = channels.governance_root()  # Exact external human-input registry, not packet fields.
    if type(root) is not GovernanceTrustRoot:
        raise Refusal("independent exact governance root required")
    authority = GitHubPreregistrationAuthority(GitHubGovernanceStore(root,
        transport=channels.native_transport()))
    prepared = prepare_run(source, MANIFEST, RunRequest(**packet["request"]), authority=authority)
    original_lock = read(packet["lock_path"])
    original_ticket = read(packet["ticket_path"])
    prefix = read(packet["prefix_path"])
    if prepared.lock_bytes != original_lock:
        raise Refusal("fresh prepared lock differs from original coordinator lock")
    ticket = validate_ticket(prepared, original_ticket)
    from smallestlie.campaign.completion_source import _prefix
    # Existing mechanical raw-chain/ticket/context check, no live acceptance.
    _prefix(prefix, prepared, ticket, None)
    # Recheck source immediately before importing the collector. No optimized
    # qualification scanner/helper, source override or monkeypatch is installed.
    authenticate_local_source(packet, originals)
    spec = importlib.util.spec_from_file_location("w3_formal_single_action", source / COLLECTOR)
    if spec is None or spec.loader is None:
        raise Refusal("frozen receiver loader unavailable")
    collector = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = collector
    spec.loader.exec_module(collector)
    installed, verifier = receiver_inputs(packet, prepared, ticket, collector, source, out)
    if packet_bytes(packet_raw) != packet:
        raise Refusal("input packet changed during source/reference validation")
    for name, raw in (("packet.raw", packet_raw), ("manifest.raw", prepared.manifest_bytes), ("lock.raw", original_lock),
                      ("ticket.raw", original_ticket), ("prefix.raw", prefix)):
        write_new(out / "entry-inputs" / name, raw)
    # All original inputs are retained before any proposed one-use release.
    # This is syntax/reference/fsync/readback only, not custody or acceptance.
    prior_sources = channels.prerequisite_sources(packet, prepared, ticket)
    dispatch = channels.session_release(packet, prepared, ticket, prefix)
    produced = collector.produce_action(prepared, ticket, prefix,
        root=out / "receiver", workspace=plain(packet["workspace_root"]),
        claims_root=plain(packet["claims_root"]), dispatch=dispatch,
        epoch=packet["epoch"], action_id=packet["action_id"], first_sequence=packet["first_sequence"],
        installation=installed, verifier=verifier, prerequisite_authorities=prior_sources,
        bounds=collector.ProducerBounds())
    # Local raw bundle only. EC retains and publishes out after native job ends.
    # There is no FormalLifecycle.begin/reserve/complete, publication or self-ACK.
    note = {"schema_version": "smallestlie.w3-entry-local-production/proposal-v1",
        "scope": "local single reserved action; external publication/acceptance pending",
        "termination_kind": produced.termination_kind,
        "completion_sha256": produced.completion_sha256,
        "publication_sha256": produced.publication_sha256}
    write_new(out / "entry-local-production.json", json.dumps(note, sort_keys=True,
        ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii"))


def main():
    if os.name != "nt" or os.environ.get("COMPUTERNAME", "").upper() != HOST:
        raise Refusal("single named pool host required")
    secret_names = ("TOKEN", "SECRET", "PASSWORD", "PRIVATE_KEY", "CREDENTIAL")
    if any(value and any(word in key.upper() for word in secret_names) for key, value in os.environ.items()):
        raise Refusal("entry received a credential-like environment variable")
    path = os.environ.get("EC_W3_ACTION_INPUT")
    if not path:
        raise UnsupportedBoundary("trusted EC input-channel step is absent")
    raw = read(path)
    packet = packet_bytes(raw)
    if len(sys.argv) != 2 or sys.argv[1] != "--private-action":
        raise UnsupportedBoundary("only the trusted direct private launcher may start this receiver")
    channels = open_admitted_ec_channels(raw)
    out = plain(os.environ["EC_WORKLOAD_OUT"])
    if len(sys.argv) == 2 and sys.argv[1] == "--private-action":
        try:
            run_private(packet, raw, channels, out)
        finally:
            # Wire close is only a framing disposition. Native exit/output/writer
            # facts and fresh later receipt authority determine completion.
            channels.native_transport().close()
        return 0  # Local raw production, never a semantic verdict/acceptance.
    raise UnsupportedBoundary("trusted direct private action required")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Refusal, OSError, KeyError, TypeError) as exc:
        # No cleanup, retry or synthetic completion; retain all already-written
        # claims/raw bytes for the external failure publisher/custody controller.
        sys.stderr.write("W3 single-action entry refused: " + type(exc).__name__ + "\n")
        raise SystemExit(6)
