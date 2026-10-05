"""Finite occurrence protocol for one pytest partition, without product imports.

SOURCE_ONLY / NOT_RUN: validation of a partition never establishes a full series.
"""

from __future__ import annotations

from collections import Counter
import hashlib
import json
import math
import re
import xml.etree.ElementTree as ET


PROTOCOL = "smallestlie-windows-pytest-partition-v1"
IDENTITY_PROPERTIES = ("sl_nodeid", "sl_ordinal", "sl_occurrence")
CONFIGURATION = {
    "args": ["tests"], "strict_markers": True, "plugin_autoload": False,
    "cache_provider": False, "timeout_plugin": True, "additional_selection": False,
}


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=False,
                       separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def _unique(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON field: {key}")
        value[key] = item
    return value


def load(raw: bytes) -> object:
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(
                          ValueError(f"non-finite JSON number: {value}")))


def parameters(raw: bytes) -> str:
    value = load(raw)
    if (type(value) is not dict or set(value) != {"shard"}
            or type(value["shard"]) is not str
            or re.fullmatch(r"[0-3]", value["shard"]) is None):
        raise ValueError("require exactly one string parameter: shard in 0..3")
    return value["shard"]


def identities(nodeids: list[str]) -> list[dict]:
    seen: Counter[str] = Counter()
    rows = []
    for ordinal, nodeid in enumerate(nodeids):
        if type(nodeid) is not str or not nodeid:
            raise ValueError("nonempty exact nodeids required")
        rows.append({"nodeid": nodeid, "ordinal": ordinal, "occurrence": seen[nodeid]})
        seen[nodeid] += 1
    return rows


def key(row: dict) -> tuple[str, int, int]:
    if (type(row) is not dict or set(row) != {"nodeid", "ordinal", "occurrence"}
            or type(row["nodeid"]) is not str or not row["nodeid"]
            or type(row["ordinal"]) is not int or row["ordinal"] < 0
            or type(row["occurrence"]) is not int or row["occurrence"] < 0):
        raise ValueError("invalid occurrence identity")
    return row["nodeid"], row["ordinal"], row["occurrence"]


def selected(rows: list[dict], shard: str) -> list[dict]:
    if type(shard) is not str or re.fullmatch(r"[0-3]", shard) is None:
        raise ValueError("invalid fixed shard")
    return [row for row in rows if int(digest(key(row)[0].encode("utf-8")), 16) % 4 == int(shard)]


def inventory(raw: bytes) -> dict:
    value = load(raw)
    fields = {"schema_version", "protocol", "source_sha", "lock_sha256", "plugin_sha256",
              "pytest_version", "configuration", "items"}
    if (type(value) is not dict or set(value) != fields
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["protocol"] != PROTOCOL
            or canonical(value["configuration"]) != canonical(CONFIGURATION)
            or type(value["pytest_version"]) is not str or not value["pytest_version"]
            or type(value["source_sha"]) is not str
            or re.fullmatch(r"[0-9a-f]{40}", value["source_sha"]) is None
            or any(type(value[field]) is not str or re.fullmatch(r"[0-9a-f]{64}", value[field]) is None
                   for field in ("lock_sha256", "plugin_sha256"))
            or type(value["items"]) is not list or not value["items"]):
        raise ValueError("invalid or empty complete collection inventory")
    rows = value["items"]
    for row in rows:
        key(row)
    if rows != identities([row["nodeid"] for row in rows]) or raw != canonical(value):
        raise ValueError("noncanonical inventory or invalid ordered multiplicity")
    return value


def _session(raw: bytes, *, mode: str, inventory_sha: str, invocations: int) -> dict:
    value = load(raw)
    fields = {"schema_version", "protocol", "mode", "inventory_sha256", "collection_complete",
              "collection_errors", "exitstatus", "plugin_loaded", "invocations_started",
              "invocations_finished", "invocations_closed"}
    if (type(value) is not dict or set(value) != fields
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["protocol"] != PROTOCOL or value["mode"] != mode
            or value["inventory_sha256"] != inventory_sha
            or value["plugin_loaded"] is not True or value["collection_complete"] is not True
            or type(value["exitstatus"]) is not int or value["exitstatus"] != 0
            or type(value["collection_errors"]) is not int or value["collection_errors"] != 0
            or type(value["invocations_started"]) is not int or value["invocations_started"] != invocations
            or type(value["invocations_finished"]) is not int or value["invocations_finished"] != invocations
            or value["invocations_closed"] is not True):
        raise ValueError("missing or unsuccessful plugin terminal handshake")
    return value


def collection_result(raw_inventory: bytes, raw_session: bytes, raw_events: bytes, *, code: int,
                      source_sha: str, lock_sha: str, plugin_sha: str) -> dict:
    value = inventory(raw_inventory)
    if code != 0 or (value["source_sha"], value["lock_sha256"], value["plugin_sha256"]) != (
            source_sha, lock_sha, plugin_sha):
        raise ValueError("collection exit or exact source closure mismatch")
    terminal = _session(raw_session, mode="collect", inventory_sha=digest(raw_inventory), invocations=0)
    records = [load(line) for line in raw_events.splitlines()]
    if records != [
        {"event": "collection_finished", "inventory_sha256": digest(raw_inventory),
         "selected": value["items"], "mode": "collect"},
        {"event": "session_end", **terminal},
    ]:
        raise ValueError("missing or incorrect complete collection stream handshake")
    return value


def partition_result(raw_inventory: bytes, raw_assignment: bytes, raw_events: bytes,
                     raw_session: bytes, raw_junit: bytes, *, shard: str, code: int) -> dict:
    """Reconcile all occurrence identities, three raw phases and genuine JUnit."""
    value = inventory(raw_inventory)
    rows = selected(value["items"], shard)
    if code != 0 or not rows:
        raise ValueError("partition exit must be zero with a nonempty selection")
    inventory_sha = digest(raw_inventory)
    assignment = load(raw_assignment)
    expected_assignment = {
        "schema_version": 1, "protocol": PROTOCOL, "plugin_loaded": True,
        "mode": "execute", "shard": shard, "inventory_sha256": inventory_sha,
        "assignment_rule": "sha256(nodeid_utf8)_mod_4", "selected": rows,
    }
    if assignment != expected_assignment or raw_assignment != canonical(expected_assignment):
        raise ValueError("missing or incorrect plugin assignment handshake")
    terminal = _session(raw_session, mode="execute", inventory_sha=inventory_sha, invocations=len(rows))
    records = [load(line) for line in raw_events.splitlines()]
    if (not records or any(type(record) is not dict for record in records)
            or records[-1] != {"event": "session_end", **terminal}):
        raise ValueError("missing terminal phase stream record")
    if records[0] != {"event": "collection_finished", "inventory_sha256": inventory_sha,
                       "selected": rows, "mode": "execute"}:
        raise ValueError("execution stream does not begin with authenticated collection")
    expected_keys = {key(row) for row in rows}
    phases = {identity: {} for identity in expected_keys}
    collection_events = 0
    observed_order = []
    locations = {}
    for record in records[:-1]:
        if record.get("event") == "collection_finished":
            if record != {"event": "collection_finished", "inventory_sha256": inventory_sha,
                          "selected": rows, "mode": "execute"}:
                raise ValueError("collection identity stream mismatch")
            collection_events += 1
            continue
        if record.get("event") in {"logstart", "logfinish"}:
            if set(record) != {"event", "identity", "nodeid", "location"}:
                raise ValueError("invalid actual invocation boundary record")
            identity = key(record["identity"])
            location = record["location"]
            if (identity not in expected_keys or record["nodeid"] != identity[0]
                    or type(location) is not list or len(location) != 3
                    or type(location[0]) is not str or type(location[1]) is not int
                    or location[1] < 0 or type(location[2]) is not str):
                raise ValueError("actual boundary nodeid/location differs from selected occurrence")
            if record["event"] == "logstart":
                if identity in locations:
                    raise ValueError("duplicate actual invocation start")
                locations[identity] = location
            elif identity not in locations or locations[identity] != location:
                raise ValueError("actual invocation finish lacks matching start")
            observed_order.append((identity, record["event"]))
            continue
        if set(record) != {"event", "identity", "when", "outcome", "wasxfail", "duration"}:
            raise ValueError("unexpected raw phase record")
        identity = key(record["identity"])
        when = record["when"]
        if (record["event"] != "phase" or identity not in expected_keys
                or when not in {"setup", "call", "teardown"} or when in phases[identity]
                or record["outcome"] != "passed" or record["wasxfail"] is not False
                or type(record["duration"]) not in {int, float}
                or not math.isfinite(record["duration"]) or record["duration"] < 0):
            raise ValueError("extra, duplicate, missing, failed, skipped or xfail raw phase")
        phases[identity][when] = record
        observed_order.append((identity, when))
    if collection_events != 1 or any(set(phase) != {"setup", "call", "teardown"}
                                     for phase in phases.values()):
        raise ValueError("incomplete collection or three-phase occurrence coverage")
    if observed_order != [(key(row), event) for row in rows
                         for event in ("logstart", "setup", "call", "teardown", "logfinish")]:
        raise ValueError("raw execution occurrence or phase order changed")
    root = ET.fromstring(raw_junit)
    if root.tag not in {"testsuite", "testsuites"}:
        raise ValueError("unexpected JUnit document")
    cases = root.findall(".//testcase")
    if not cases:
        raise ValueError("empty genuine JUnit")
    # Also reject suite-level error/skip/failure records, not only testcase children.
    if any(any(True for _ in root.iter(tag)) for tag in ("failure", "error", "skipped")):
        raise ValueError("JUnit failure, error or skip")
    junit_keys = []
    for case in cases:
        props = [(prop.get("name"), prop.get("value"))
                 for prop in case.findall("./properties/property")]
        own = [(name, val) for name, val in props if name and name.startswith("sl_")]
        if (len(own) != 3 or Counter(name for name, _ in own) != Counter(IDENTITY_PROPERTIES)
                or any(type(val) is not str for _, val in own)):
            raise ValueError("missing, extra or duplicate JUnit identity property")
        attrs = dict(own)
        if any(re.fullmatch(r"0|[1-9][0-9]*", attrs[name]) is None
               for name in ("sl_ordinal", "sl_occurrence")):
            raise ValueError("noncanonical JUnit identity integer")
        junit_keys.append(key({"nodeid": attrs["sl_nodeid"], "ordinal": int(attrs["sl_ordinal"]),
                              "occurrence": int(attrs["sl_occurrence"])}))
    if Counter(junit_keys) != Counter(key(row) for row in rows):
        raise ValueError("JUnit missing, extra or duplicate selected occurrence")
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    for suite in suites:
        for attr in ("failures", "errors", "skipped"):
            if suite.get(attr) != "0":
                raise ValueError("missing or nonzero JUnit suite failure/error/skip count")
    if sum(int(suite.attrib["tests"]) for suite in suites) != len(rows):
        raise ValueError("JUnit declared denominator mismatch")
    return {"tests": len(rows), "failures": 0, "errors": 0, "skipped": 0,
            "inventory_sha256": inventory_sha, "selected": rows,
            "scope": "partition_phases_only", "phase_checks_complete": True}
