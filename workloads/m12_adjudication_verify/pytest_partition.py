"""Explicit pytest plugin: retain full collection, execute one fixed partition.

SOURCE_ONLY / NOT_RUN until remote qualification. No XML is synthesized here;
identity properties attach to actual pytest items and their actual reports.
"""

from __future__ import annotations

import os
from pathlib import Path
import re

import pytest

from workloads.m12_adjudication_verify.protocol import (
    CONFIGURATION, IDENTITY_PROPERTIES, PROTOCOL, canonical, digest, identities,
    inventory, selected,
)
from workloads.m12_adjudication_verify.output_bound import OutputBudget, bind_junit, close_preserving_primary

_session_state = None


def pytest_addoption(parser):
    group = parser.getgroup("smallestlie-fixed-partition")
    group.addoption("--sl-partition-mode", choices=("collect", "execute"))
    group.addoption("--sl-partition-inventory")
    group.addoption("--sl-partition-evidence")
    group.addoption("--sl-partition-shard")
    group.addoption("--sl-partition-source-sha")
    group.addoption("--sl-partition-lock-sha")


class State:
    def __init__(self, config):
        self.mode = config.getoption("sl_partition_mode")
        self.shard = config.getoption("sl_partition_shard")
        self.source = config.getoption("sl_partition_source_sha")
        self.lock = config.getoption("sl_partition_lock_sha")
        path = config.getoption("sl_partition_inventory")
        prefix = config.getoption("sl_partition_evidence")
        if (self.mode not in {"collect", "execute"} or not path or not prefix
                or not self.source or re.fullmatch(r"[0-9a-f]{40}", self.source) is None
                or not self.lock or re.fullmatch(r"[0-9a-f]{64}", self.lock) is None
                or (self.mode == "execute" and (type(self.shard) is not str
                    or re.fullmatch(r"[0-3]", self.shard) is None))
                or (self.mode == "collect" and self.shard is not None)):
            raise pytest.UsageError("incomplete or invalid fixed-partition protocol options")
        if (config.args != ["tests"] or not config.option.strict_markers
                or bool(config.option.collectonly) != (self.mode == "collect")
                or os.environ.get("PYTEST_DISABLE_PLUGIN_AUTOLOAD") != "1"
                or os.environ.get("PYTEST_ADDOPTS") or os.environ.get("PYTEST_PLUGINS")
                or config.pluginmanager.hasplugin("cacheprovider")
                or not config.pluginmanager.hasplugin("pytest_timeout")):
            raise pytest.UsageError("fixed complete tests collection and explicit plugins required")
        # Deny selectors even if a caller would otherwise supply a valid inventory.
        forbidden = ("keyword", "markexpr", "ignore", "ignore_glob", "deselect", "pyargs",
                     "keepduplicates", "continue_on_collection_errors", "lf", "ff", "nf",
                     "stepwise", "stepwise_skip")
        if any(getattr(config.option, name, None) for name in forbidden):
            raise pytest.UsageError("additional pytest selection is forbidden")
        self.path = Path(path)
        self.prefix = Path(prefix)
        self.prefix.parent.mkdir(parents=True, exist_ok=True)
        self.output = OutputBudget.child(expected_stage='collection' if self.mode=='collect' else 'partition')
        self.events = self.output.open(Path(str(self.prefix) + ".events.jsonl"))
        self.errors = 0
        self.external_deselection = False
        self.own_deselection = False
        self.complete = False
        self.raw = None
        self.rows = []
        self.items = []
        self.cursor = 0
        self.active_item = None
        self.active_identity = None
        self.invocation_open = False
        self.active_location = None
        self.invocations_started = 0
        self.invocations_finished = 0
        self.assignment = None

    def event(self, record):
        self.events.write(canonical(record))
        self.events.flush()

    def write(self, suffix, value):
        self.output.write_new(Path(str(self.prefix) + suffix), canonical(value))


@pytest.hookimpl(trylast=True)
def pytest_configure(config):
    global _session_state
    config._sl_partition = State(config)
    _session_state = config._sl_partition
    if config.option.xmlpath:
        bind_junit(config, _session_state.output)


@pytest.hookimpl(hookwrapper=True)
def pytest_make_collect_report(collector):
    outcome = yield
    report = outcome.get_result()
    state = getattr(collector.config, "_sl_partition", None)
    if state is not None and report.failed:
        state.errors += 1


def pytest_deselected(items):
    for item in items:
        state = getattr(item.config, "_sl_partition", None)
        if state is not None and not state.own_deselection:
            state.external_deselection = True


@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(session, config, items):
    state = config._sl_partition
    if state.errors or state.external_deselection or not items:
        raise pytest.UsageError("collection errors, external deselection or empty inventory")
    rows = identities([item.nodeid for item in items])
    value = {"schema_version": 1, "protocol": PROTOCOL, "source_sha": state.source,
             "lock_sha256": state.lock, "plugin_sha256": digest(Path(__file__).read_bytes()),
             "pytest_version": pytest.__version__, "configuration": CONFIGURATION, "items": rows}
    raw = canonical(value)
    if state.mode == "collect":
        state.rows = rows
        state.raw = raw
        state.items = list(items)
        return
    # Recollect the complete ordered population before removing any other shard.
    with state.path.open("rb") as handle:
        prior = handle.read(32 * 1024 * 1024 + 1)
    if len(prior) > 32 * 1024 * 1024:
        raise pytest.UsageError("original inventory exceeds fixed evidence cap")
    inventory(prior)
    if raw != prior:
        raise pytest.UsageError("complete ordered collection drifted from original inventory")
    state.raw = prior
    state.rows = selected(rows, state.shard)
    if not state.rows:
        raise pytest.UsageError("selected partition is empty")
    wanted = {row["ordinal"] for row in state.rows}
    kept, removed = [], []
    for item, row in zip(items, rows, strict=True):
        if row["ordinal"] in wanted:
            if any(name.startswith("sl_") for name, _ in item.user_properties):
                raise pytest.UsageError("reserved occurrence properties already present")
            kept.append(item)
        else:
            removed.append(item)
    state.own_deselection = True
    try:
        config.hook.pytest_deselected(items=removed)
    finally:
        state.own_deselection = False
    items[:] = kept
    state.items = list(kept)
    state.assignment = {
        "schema_version": 1, "protocol": PROTOCOL, "plugin_loaded": True,
        "mode": "execute", "shard": state.shard, "inventory_sha256": digest(prior),
        "assignment_rule": "sha256(nodeid_utf8)_mod_4", "selected": state.rows,
    }


@pytest.hookimpl(trylast=True)
def pytest_collection_finish(session):
    state = session.config._sl_partition
    if (state.raw is None or state.errors or state.external_deselection
            or session.items != state.items or not state.items
            or [item.nodeid for item in session.items] != [row["nodeid"] for row in state.rows]):
        raise pytest.UsageError("incomplete or subsequently modified collection")
    if state.mode == "collect":
        state.output.write_new(state.path, state.raw)
    else:
        state.write(".assignment.json", state.assignment)
    state.complete = True
    state.event({"event": "collection_finished", "inventory_sha256": digest(state.raw),
                 "selected": state.rows, "mode": state.mode})


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_protocol(item, nextitem):
    state = item.config._sl_partition
    if (state.mode != "execute" or not state.complete or state.cursor >= len(state.rows)
            or item is not state.items[state.cursor]):
        raise pytest.UsageError("execution occurrence order differs from assignment")
    state.active_item = item
    state.active_identity = state.rows[state.cursor]
    # A repeated nodeid, or even a repeated item object, gets a fresh occurrence
    # identity for its actual invocation. Never collapse the ordered population.
    item.user_properties[:] = [(name, val) for name, val in item.user_properties
                               if name not in IDENTITY_PROPERTIES]
    row = state.active_identity
    item.user_properties.extend(zip(IDENTITY_PROPERTIES, (
        row["nodeid"], str(row["ordinal"]), str(row["occurrence"])), strict=True))
    try:
        yield
    finally:
        state.cursor += 1
        state.active_item = None
        state.active_identity = None


def _boundary(event, nodeid, location):
    state = _session_state
    if (state is None or state.mode != "execute" or not state.complete
            or state.active_item is None or state.active_identity is None
            or nodeid != state.active_identity["nodeid"]):
        raise pytest.UsageError("actual invocation boundary lacks the selected occurrence")
    actual_location = list(location)
    if event == "logstart":
        if state.invocation_open:
            raise pytest.UsageError("extra or overlapping actual invocation start")
        state.invocation_open = True
        state.active_location = actual_location
        state.invocations_started += 1
    else:
        if not state.invocation_open or actual_location != state.active_location:
            raise pytest.UsageError("actual invocation finish is missing or mismatched")
        state.invocations_finished += 1
    state.event({"event": event, "identity": state.active_identity,
                 "nodeid": nodeid, "location": actual_location})
    if event == "logfinish":
        state.invocation_open = False
        state.active_location = None


def pytest_runtest_logstart(nodeid, location):
    _boundary("logstart", nodeid, location)


def pytest_runtest_logfinish(nodeid, location):
    _boundary("logfinish", nodeid, location)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    state = item.config._sl_partition
    identity = state.active_identity
    if state.mode != "execute" or not state.complete or identity is None or state.active_item is not item:
        raise pytest.UsageError("execution without authenticated partition assignment")
    # Actual report properties are what pytest's own JUnit writer records.
    report.user_properties = list(item.user_properties)
    report._sl_partition_state = state
    report._sl_partition_identity = identity


def pytest_runtest_logreport(report):
    # Read the completed report after every makereport wrapper has applied xfail
    # semantics; an inner wrapper alone could miss a later non-strict xpass.
    state = getattr(report, "_sl_partition_state", None)
    identity = getattr(report, "_sl_partition_identity", None)
    if state is None or identity is None:
        raise pytest.UsageError("actual phase report lacks occurrence handshake")
    if not state.invocation_open or report.nodeid != identity["nodeid"]:
        raise pytest.UsageError("actual phase nodeid differs from selected occurrence")
    state.event({"event": "phase", "identity": identity, "when": report.when,
                 "outcome": report.outcome, "wasxfail": hasattr(report, "wasxfail"),
                 "duration": report.duration})


@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus):
    state = getattr(session.config, "_sl_partition", None)
    if state is None:
        return
    value = {"schema_version": 1, "protocol": PROTOCOL, "mode": state.mode,
             "inventory_sha256": digest(state.raw) if state.raw is not None else None,
             "collection_complete": state.complete, "collection_errors": state.errors,
             "exitstatus": int(exitstatus), "plugin_loaded": True,
             "invocations_started": state.invocations_started,
             "invocations_finished": state.invocations_finished,
             "invocations_closed": not state.invocation_open}
    try:
        state.event({"event": "session_end", **value})
        state.write(".session.json", value)
    finally:
        close_preserving_primary(state.events)


def pytest_unconfigure(config):
    global _session_state
    state = getattr(config, "_sl_partition", None)
    if state is not None and not state.events.closed:
        close_preserving_primary(state.events)
    _session_state = None
