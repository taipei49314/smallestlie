"""Real tiny pytest subprocess contracts; run only on authorized CI/pool hosts.

SOURCE_ONLY / NOT_RUN locally under POLICY work-machine-local. Fixtures live in
pytest's temporary directory, outside the product tests population, so an outer
partition can collect these tests without recursively collecting their inputs.
"""

from __future__ import annotations

from collections import Counter
import copy
import json
import io
import os
from pathlib import Path
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from workloads.m12_adjudication_verify import partitioned as harness
from workloads.m12_adjudication_verify import protocol as wire
from workloads.m12_adjudication_verify.output_bound import OutputBudget


PLUGIN = "workloads.m12_adjudication_verify.pytest_partition"
SOURCE = "a" * 40
LOCK = "b" * 64


class TinyPytest:
    def __init__(self, root: Path, *, subject="pass", conftest=""):
        self.root = root
        self.root.mkdir()
        (root / "tests").mkdir()
        (root / "pyproject.toml").write_text(
            "[tool.pytest.ini_options]\ntimeout = 10\n", encoding="utf-8")
        # Find a real synthetic item in each fixed shard, without guessing hash
        # distribution. This runs only inside the remote test, never on intake.
        names = {}
        for candidate in range(1000):
            name = f"test_partition_{candidate}"
            shard = str(int(wire.digest(f"tests/test_sample.py::{name}".encode()), 16) % 4)
            names.setdefault(shard, name)
            if len(names) == 4:
                break
        assert len(names) == 4
        self.shard = str(int(wire.digest(b"tests/test_sample.py::test_subject"), 16) % 4)
        body = "import pytest\n\n" + "\n".join(f"def {name}():\n    pass\n" for name in names.values())
        body += "\ndef test_subject(request):\n    " + subject.replace("\n", "\n    ") + "\n"
        (root / "tests/test_sample.py").write_text(body, encoding="utf-8")
        if conftest:
            (root / "tests/conftest.py").write_text(conftest, encoding="utf-8")
        self.inventory_path = root / "inventory.json"
        self.env = harness.child_environment(dict(os.environ), ROOT)
        self.env["PYTHONPATH"] = str(ROOT)
        deadline = time.monotonic() + 1800  # Synthetic fixture clock only, never entry authority.
        OutputBudget(root, deadline, create=True)
        self.env.update(SL_OUTPUT_ROOT=str(root), SL_OUTPUT_DEADLINE=str(deadline))

    def run(self, name: str, mode: str, *, shard=None, extra=(), plugin=True):
        prefix = self.root / name
        command = [sys.executable, "-X", "utf8", "-B", "-m", "pytest", "-q", "--strict-markers", "--capture=no",
                   "-p", "pytest_timeout", "-p", "no:cacheprovider", "-c", "pyproject.toml",
                   "-o", "addopts=", "--basetemp", str(self.root / (name + "-temp"))]
        if plugin:
            command += ["-p", PLUGIN, "--sl-partition-mode", mode,
                        "--sl-partition-inventory", str(self.inventory_path),
                        "--sl-partition-evidence", str(prefix),
                        "--sl-partition-source-sha", SOURCE, "--sl-partition-lock-sha", LOCK]
            if mode == "execute":
                command += ["--sl-partition-shard", shard or self.shard]
        if mode == "collect":
            command += ["--collect-only"]
        else:
            command += ["--junitxml", str(prefix) + ".xml"]
        result = subprocess.run(command + list(extra) + ["tests"], cwd=self.root, env=self.env,
                                capture_output=True, timeout=30, check=False)
        (self.root / (name + ".stdout")).write_bytes(result.stdout)
        (self.root / (name + ".stderr")).write_bytes(result.stderr)
        return result

    def collect(self):
        result = self.run("collect", "collect")
        assert result.returncode == 0, result.stdout + result.stderr
        raw = self.inventory_path.read_bytes()
        plugin_sha = wire.digest((ROOT / "workloads/m12_adjudication_verify/pytest_partition.py").read_bytes())
        value = wire.collection_result(raw, (self.root / "collect.session.json").read_bytes(),
            (self.root / "collect.events.jsonl").read_bytes(), code=result.returncode,
            source_sha=SOURCE, lock_sha=LOCK, plugin_sha=plugin_sha)
        return raw, value

    def evidence(self, name="execute", *, code=0, shard=None):
        return {
            "raw_inventory": self.inventory_path.read_bytes(),
            "raw_assignment": (self.root / (name + ".assignment.json")).read_bytes(),
            "raw_events": (self.root / (name + ".events.jsonl")).read_bytes(),
            "raw_session": (self.root / (name + ".session.json")).read_bytes(),
            "raw_junit": (self.root / (name + ".xml")).read_bytes(),
            "shard": shard or self.shard, "code": code,
        }


@pytest.fixture
def complete_evidence(tmp_path):
    tiny = TinyPytest(tmp_path / "fixture")
    tiny.collect()
    result = tiny.run("execute", "execute")
    assert result.returncode == 0, result.stdout + result.stderr
    evidence = tiny.evidence()
    wire.partition_result(**evidence)
    return evidence


def test_real_four_partitions_cover_ordered_duplicate_occurrences(tmp_path):
    tiny = TinyPytest(tmp_path / "fixture", conftest=(
        "def pytest_collection_modifyitems(items):\n"
        "    items.append(items[0])\n"))
    raw, value = tiny.collect()
    rows = value["items"]
    repeated = [row for row in rows if row["nodeid"] == rows[0]["nodeid"]]
    assert [row["occurrence"] for row in repeated] == [0, 1]
    all_keys = []
    previous = set()
    for shard in ("0", "1", "2", "3"):
        name = "shard-" + shard
        result = tiny.run(name, "execute", shard=shard)
        assert result.returncode == 0, result.stdout + result.stderr
        evidence = tiny.evidence(name, shard=shard)
        assert evidence["raw_inventory"] == raw
        observed = wire.partition_result(**evidence)
        keys = [wire.key(row) for row in observed["selected"]]
        assert not previous.intersection(keys)
        previous.update(keys)
        all_keys.extend(keys)
    assert Counter(all_keys) == Counter(wire.key(row) for row in rows)


def test_collection_bytes_stable_across_different_output_contexts(tmp_path):
    tiny = TinyPytest(tmp_path / "fixture")
    first, _ = tiny.collect()
    other = TinyPytest(tmp_path / "second-fixture")
    result = other.run("another-context", "collect")
    assert result.returncode == 0, result.stdout + result.stderr
    assert other.inventory_path.name == "inventory.json"
    assert other.inventory_path.read_bytes() == first


@pytest.mark.parametrize("assertion_failure", (False, True))
def test_actual_quota_fault_bodies_restore_before_partition_call_hooks(tmp_path, assertion_failure):
    # Calls the actual populated source contracts, using a fixture whose
    # teardown occurs AFTER the genuine partition plugin's call logreport.
    subject = (
        "import os, sys\nfrom pathlib import Path\n"
        "from workloads.m12_adjudication_verify import output_bound as bound, pipe_capture as pipes\n"
        "sys.path.insert(0, str(Path(os.environ['PYTHONPATH']) / 'tests' / 'unit'))\n"
        "import test_windows_output_bound as faults\n"
        "before = (bound.TOTAL, bound.PAGE, pipes.PAGE, dict(bound.CAPS))\n"
        "patch = request.getfixturevalue('monkeypatch')\n"
        "root = request.getfixturevalue('tmp_path')\n"
    )
    if assertion_failure:
        subject += (
            "original = Path.read_bytes\n"
            "def wrong_read(path):\n"
            "    return b'assertion fault' if path.name == 'focused.stdout' else original(path)\n"
            "with pytest.MonkeyPatch.context() as injected:\n"
            "    injected.setattr(Path, 'read_bytes', wrong_read)\n"
            "    with pytest.raises(AssertionError):\n"
            "        faults.test_aggregate_prepaid_read_refusal_happens_before_pipe_read(root, patch)\n"
        )
    else:
        subject += (
            "names = ('test_per_file_refuses_before_excess_and_preserves_original_calls',\n"
            "         'test_aggregate_prepaid_read_refusal_happens_before_pipe_read',\n"
            "         'test_fragmented_actual_sentinel_is_retained_and_not_complete',\n"
            "         'test_unused_receive_window_stays_charged_and_eof_is_actual',\n"
            "         'test_genuine_junit_bound_is_one_instance_and_keeps_original_provider')\n"
            "for index, name in enumerate(names):\n"
            "    case = root / str(index)\n    case.mkdir()\n"
            "    getattr(faults, name)(case, patch)\n"
            "    assert (bound.TOTAL, bound.PAGE, pipes.PAGE, dict(bound.CAPS)) == before\n"
        )
    subject += "assert (bound.TOTAL, bound.PAGE, pipes.PAGE, dict(bound.CAPS)) == before\nassert request.config.option.capture == 'no'"
    tiny = TinyPytest(tmp_path / "fixture", subject=subject)
    tiny.collect()
    result = tiny.run("execute", "execute")
    assert result.returncode == 0, result.stdout + result.stderr
    evidence = tiny.evidence()
    wire.partition_result(**evidence)
    records = [wire.load(line) for line in evidence["raw_events"].splitlines()]
    subject_rows = [row for row in records if row.get("identity", {}).get("nodeid", "").endswith("::test_subject")]
    assert [(row["when"], row["outcome"]) for row in subject_rows if row["event"] == "phase"] == [
        ("setup", "passed"), ("call", "passed"), ("teardown", "passed")]
    assert [row["event"] for row in subject_rows if row["event"] != "phase"] == ["logstart", "logfinish"]
    assert not (tiny.root / "output-refusal.json").exists()


@pytest.mark.parametrize("subject,conftest", [
    ("pytest.skip('real skip')", ""),
    ("pytest.fail('call failed')", ""),
    ("pass", "import pytest\n@pytest.fixture(autouse=True)\ndef setup():\n    pytest.fail('setup failed')\n"),
    ("pass", "import pytest\n@pytest.fixture(autouse=True)\ndef teardown():\n    yield\n    pytest.fail('teardown failed')\n"),
    ("pytest.xfail('runtime expected failure')", ""),
    ("pass", "import pytest\ndef pytest_collection_modifyitems(items):\n"
     "    for item in items:\n        if item.name == 'test_subject':\n"
     "            item.add_marker(pytest.mark.xfail(strict=False))\n"),
])
def test_real_unsuccessful_or_xpass_phases_never_complete(tmp_path, subject, conftest):
    tiny = TinyPytest(tmp_path / "fixture", subject=subject, conftest=conftest)
    tiny.collect()
    result = tiny.run("execute", "execute")
    # Even exit-zero skip/xfail/non-strict xpass must be refused by raw phases/XML.
    with pytest.raises((ValueError, ET.ParseError)):
        wire.partition_result(**tiny.evidence(code=result.returncode))


@pytest.mark.parametrize("kind", ("empty", "collection_error", "external_deselection"))
def test_real_collection_refuses_incomplete_population(tmp_path, kind):
    conftest = ("def pytest_collection_modifyitems(config, items):\n"
                "    config.hook.pytest_deselected(items=[items.pop()])\n") if kind == "external_deselection" else ""
    tiny = TinyPytest(tmp_path / "fixture", conftest=conftest)
    if kind == "empty":
        (tiny.root / "tests/test_sample.py").write_text("", encoding="utf-8")
    elif kind == "collection_error":
        (tiny.root / "tests/test_sample.py").write_text("raise RuntimeError('collection error')\n", encoding="utf-8")
    result = tiny.run("collect", "collect")
    assert result.returncode != 0
    assert not tiny.inventory_path.exists()


def test_recollection_detects_real_ordered_denominator_drift(tmp_path):
    tiny = TinyPytest(tmp_path / "fixture")
    raw, _ = tiny.collect()
    path = tiny.root / "tests/test_sample.py"
    with path.open("a", encoding="utf-8") as handle:
        handle.write("\ndef test_new_item():\n    pass\n")
    result = tiny.run("execute", "execute")
    assert result.returncode != 0
    assert tiny.inventory_path.read_bytes() == raw
    assert not (tiny.root / "execute.assignment.json").exists()


@pytest.mark.parametrize("selector", [("-k", "subject"), ("-m", "integration"),
                                     ("--ignore", "tests/test_sample.py"),
                                     ("--deselect", "tests/test_sample.py::test_subject")])
def test_additional_pytest_selection_refused_before_partition(tmp_path, selector):
    tiny = TinyPytest(tmp_path / "fixture")
    tiny.collect()
    result = tiny.run("execute", "execute", extra=selector)
    assert result.returncode != 0
    assert not (tiny.root / "execute.assignment.json").exists()


def test_missing_plugin_cannot_turn_real_full_xml_into_partition_completion(tmp_path):
    tiny = TinyPytest(tmp_path / "fixture")
    tiny.collect()
    result = tiny.run("without-plugin", "execute", plugin=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert (tiny.root / "without-plugin.xml").exists()
    with pytest.raises(ValueError):
        wire.partition_result(tiny.inventory_path.read_bytes(), b"{}", b"", b"{}",
                              (tiny.root / "without-plugin.xml").read_bytes(),
                              shard=tiny.shard, code=result.returncode)


def test_actual_test_removing_reserved_properties_cannot_complete(tmp_path):
    tiny = TinyPytest(tmp_path / "fixture", subject="request.node.user_properties[:] = []")
    tiny.collect()
    result = tiny.run("execute", "execute")
    assert result.returncode == 0, result.stdout + result.stderr
    with pytest.raises(ValueError, match="JUnit identity"):
        wire.partition_result(**tiny.evidence())


@pytest.mark.parametrize("xpass", (False, True))
def test_focused_guard_reads_final_real_xpass_outcome(tmp_path, xpass):
    conftest = ("import pytest\ndef pytest_collection_modifyitems(items):\n"
                "    for item in items:\n        if item.name == 'test_subject':\n"
                "            item.add_marker(pytest.mark.xfail(strict=False))\n") if xpass else ""
    tiny = TinyPytest(tmp_path / "fixture", conftest=conftest)
    name = "diagnostic"
    result = tiny.run(name, "execute", plugin=False, extra=(
        "-p", "workloads.m12_adjudication_verify.pytest_outcome_guard",
        "--sl-outcome-evidence", str(tiny.root / name)))
    assert result.returncode == 0, result.stdout + result.stderr
    args = (tiny.root / (name + ".xml"), result.returncode,
            (tiny.root / (name + ".session.json")).read_bytes(),
            (tiny.root / (name + ".events.jsonl")).read_bytes())
    if xpass:
        with pytest.raises(ValueError, match="xfail/xpass"):
            harness.focused_result(*args)
    else:
        assert harness.focused_result(*args)["tests"] > 0


@pytest.mark.parametrize("mutation", ("missing", "extra", "duplicate", "wrong_identity", "duplicate_property"))
def test_real_junit_identity_negative_contracts(complete_evidence, mutation):
    evidence = dict(complete_evidence)
    root = ET.fromstring(evidence["raw_junit"])
    suite = root.find("testsuite")
    assert suite is not None
    case = suite.find("testcase")
    assert case is not None
    props = case.find("properties")
    assert props is not None
    if mutation == "missing":
        suite.remove(case)
    elif mutation in {"extra", "duplicate"}:
        another = copy.deepcopy(case)
        if mutation == "extra":
            another.find("properties/property[@name='sl_nodeid']").set("value", "extra::identity")
        suite.append(another)
    elif mutation == "wrong_identity":
        props.find("property[@name='sl_nodeid']").set("value", "wrong::identity")
    else:
        props.append(copy.deepcopy(props.find("property[@name='sl_ordinal']")))
    evidence["raw_junit"] = ET.tostring(root)
    with pytest.raises(ValueError):
        wire.partition_result(**evidence)


@pytest.mark.parametrize("mutation", ("missing_setup", "missing_teardown", "duplicate_phase",
                                     "reordered", "missing_terminal", "missing_session",
                                     "missing_assignment", "partial_xml"))
def test_partial_or_ambiguous_raw_originals_never_complete(complete_evidence, mutation):
    evidence = dict(complete_evidence)
    records = [wire.load(line) for line in evidence["raw_events"].splitlines()]
    if mutation.startswith("missing_") and mutation in {"missing_setup", "missing_teardown"}:
        when = mutation.removeprefix("missing_")
        index = next(i for i, row in enumerate(records) if row.get("when") == when)
        records.pop(index)
    elif mutation == "duplicate_phase":
        index = next(i for i, row in enumerate(records) if row.get("event") == "phase")
        records.insert(index, records[index])
    elif mutation == "reordered":
        records[1], records[2] = records[2], records[1]
    elif mutation == "missing_terminal":
        records.pop()
    elif mutation == "missing_assignment":
        evidence["raw_assignment"] = b"{}"
    elif mutation == "missing_session":
        evidence["raw_session"] = b"{}"
    else:
        evidence["raw_junit"] = evidence["raw_junit"][:32]
    evidence["raw_events"] = b"".join(wire.canonical(row) for row in records)
    with pytest.raises((ValueError, ET.ParseError)):
        wire.partition_result(**evidence)


@pytest.mark.parametrize("mutation", ("missing_start", "missing_finish", "duplicate_start",
                                     "extra_finish", "boundary_nodeid", "boundary_location"))
def test_actual_invocation_boundaries_are_required_and_ordered(complete_evidence, mutation):
    evidence = dict(complete_evidence)
    records = [wire.load(line) for line in evidence["raw_events"].splitlines()]
    start = next(i for i, row in enumerate(records) if row.get("event") == "logstart")
    finish = next(i for i, row in enumerate(records) if row.get("event") == "logfinish")
    if mutation == "missing_start":
        records.pop(start)
    elif mutation == "missing_finish":
        records.pop(finish)
    elif mutation == "duplicate_start":
        records.insert(start, copy.deepcopy(records[start]))
    elif mutation == "extra_finish":
        records.insert(finish, copy.deepcopy(records[finish]))
    elif mutation == "boundary_nodeid":
        records[start]["nodeid"] = "other::invocation"
    else:
        records[finish]["location"][1] += 1
    evidence["raw_events"] = b"".join(wire.canonical(row) for row in records)
    with pytest.raises(ValueError):
        wire.partition_result(**evidence)


@pytest.mark.parametrize("raw", [b"{}", b'{"shard":0}', b'{"shard":true}', b'{"shard":null}',
                                 b'{"shard":"4"}', b'{"shard":"0","other":"x"}',
                                 b'{"shard":"0","shard":"1"}', b'[]', b'null'])
def test_required_exact_parameters_never_fall_back(raw):
    with pytest.raises(ValueError):
        wire.parameters(raw)


def test_valid_parameters_preserve_exact_explicit_shard():
    assert [wire.parameters(json.dumps({"shard": shard}).encode()) for shard in ("0", "1", "2", "3")] == ["0", "1", "2", "3"]


def test_tokenless_environment_excludes_credentials_and_overrides():
    parent = {"PATH": "os-path", "SystemRoot": "C:\\Windows", "COMPUTERNAME": "host",
              "EC_WORKLOAD_APP_KEY": "secret", "GH_TOKEN": "secret", "GITHUB_TOKEN": "secret",
              "GITHUB_OUTPUT": "command-file", "PYTEST_ADDOPTS": "-k omit", "PYTEST_PLUGINS": "evil",
              "PYTHONSTARTUP": "evil.py", "GIT_CONFIG_VALUE_0": "evil"}
    child = harness.child_environment(parent, ROOT)
    assert not set(parent).intersection(child).intersection({"EC_WORKLOAD_APP_KEY", "GH_TOKEN",
        "GITHUB_TOKEN", "GITHUB_OUTPUT", "PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTHONSTARTUP"})
    assert child["GIT_CONFIG_VALUE_0"] == "NUL"
    assert child["PATH"] == "os-path"


def test_setup_and_focused_consumption_reduce_the_same_entry_deadline():
    now = [100.0]
    budget = harness.Budget(clock=lambda: now[0])
    assert budget.timeout(1600) == 1600
    now[0] += 240 + 60 + 300 + 120
    assert budget.timeout(1600) == 940
    now[0] += 940
    with pytest.raises(harness.BudgetExhausted):
        budget.timeout(1)
    assert budget.timeout(15, final=True) == 15
    now[0] += 140
    with pytest.raises(harness.BudgetExhausted):
        budget.timeout(1, final=True, closing=True)


def test_budget_refuses_native_spawn_and_retains_raw_failure(tmp_path, monkeypatch):
    budget = harness.Budget(seconds=100, clock=lambda: 0.0)
    def forbidden(*args, **kwargs):
        raise AssertionError("must not start a child without the reserve")
    monkeypatch.setattr(harness.subprocess, "Popen", forbidden)
    runner = harness.Runner(tmp_path, tmp_path, {}, budget)
    with pytest.raises(harness.BudgetExhausted): runner.run("initial-source", ["must-not-start"], 10)
    assert runner.steps[0]["started"] is False
    assert runner.steps[0]["budget_exhausted"] is True
    assert wire.load((tmp_path / "output-refusal.json").read_bytes())["primary_type"] == "BudgetExhausted"


def test_real_timeout_retains_native_prefix_and_cannot_complete(tmp_path):
    env = harness.child_environment(dict(os.environ), ROOT)
    runner = harness.Runner(tmp_path, tmp_path, env, harness.Budget())
    code = runner.run("focused", [sys.executable, "-I", "-B", "-c",
        "import time; print('original-prefix', flush=True); time.sleep(30)"], 2)
    assert code == 124
    assert runner.steps[0]["timed_out"] is True
    assert b"original-prefix" in (tmp_path / "focused.stdout").read_bytes()
    assert not (tmp_path / "partition.xml").exists()


def test_native_creation_does_not_restart_phase_timeout(tmp_path, monkeypatch):
    now = [0.0]
    budget = harness.Budget(clock=lambda: now[0])
    runner = harness.Runner(tmp_path, tmp_path, {}, budget)
    class SlowStart:
        pid = 999999
        def __init__(self, *args, **kwargs):
            now[0] += 20
            self.args = args[0]
            self.stdout, self.stderr = io.BytesIO(), io.BytesIO()
        def poll(self): return None
        def wait(self, *, timeout):
            raise AssertionError("a late native start must not receive a new relative phase cap")
    monkeypatch.setattr(harness.subprocess, "Popen", SlowStart)
    monkeypatch.setattr(runner, "_close_child", lambda process: {"tree_kill": "UNCONFIRMED"})
    assert runner.run("focused", ["synthetic"], 10) == 124
    assert runner.steps[0]["timed_out"] is True
    assert runner.steps[0]["allocated_seconds"] <= 10


def _phase_ready_result():
    # A synthetic finalization candidate, not a source/Windows execution proof.
    return {"schema_version": 1, "scope": "partition_only", "phase_checks_complete": True,
            "partition_complete": False, "shard": "0", "actual_sha": SOURCE,
            "host": "synthetic", "problems": [], "errors": [], "limitations": []}


@pytest.mark.parametrize("delayed_path", ("result.provisional.json", "result.commit.tmp",
                                        "SUMMARY.md", "terminal.json"))
def test_finalization_io_crossing_same_deadline_refuses_after_write(tmp_path, monkeypatch, delayed_path):
    now = [0.0]
    budget = harness.Budget(clock=lambda: now[0])
    now[0] = 1799.0
    original = harness.write_new
    def delayed(path, raw):
        original(path, raw)
        if path.name == delayed_path:
            now[0] += 2
    monkeypatch.setattr(harness, "write_new", delayed)
    assert harness.finalize(tmp_path, _phase_ready_result(), budget) == 1
    if (tmp_path / "result.json").exists():
        result = wire.load((tmp_path / "result.json").read_bytes())
        assert result["partition_complete"] is False
    refusal = wire.load((tmp_path / "output-refusal.json").read_bytes())
    assert refusal["error_type"] == "EntryDeadlineExceeded"
    assert refusal["entry_elapsed_seconds"] > 1800
    assert wire.load((tmp_path / "result.provisional.json").read_bytes())["partition_complete"] is False
    if delayed_path == "terminal.json":
        # The prior marker is retained, but refusal + native exit 1 makes its
        # closed predicate false. No artifact may override those observations.
        assert (tmp_path / "terminal.json").exists()
        assert (tmp_path / "result.pre-refusal.json").exists()


def test_closed_artifacts_require_actual_native_terminal_even_before_deadline(tmp_path):
    budget = harness.Budget(clock=lambda: 0.0)
    assert harness.finalize(tmp_path, _phase_ready_result(), budget) == 0
    result_raw = (tmp_path / "result.json").read_bytes()
    result = wire.load(result_raw)
    marker = wire.load((tmp_path / "terminal.json").read_bytes())
    assert result["partition_complete"] is False
    assert result["phase_checks_complete"] is True
    assert result["terminal_state"] == "NATIVE_TERMINAL_REQUIRED"
    assert marker["ready_for_native_terminal"] is True
    assert marker["partition_complete"] is False
    assert marker["result_sha256"] == wire.digest(result_raw)
    assert marker["completion_predicate"]["required_actual_wrapper_exit_code"] == 0
    assert marker["completion_predicate"]["actual_wrapper_elapsed_at_most"] == 1800
    assert not (tmp_path / "late-refusal.json").exists()


def test_finalization_exception_message_is_not_serialized_as_evidence(tmp_path, monkeypatch):
    original = harness.write_new
    def failing(path, raw):
        if path.name == "SUMMARY.md":
            raise OSError("SECRET_EXCEPTION_PAYLOAD")
        original(path, raw)
    monkeypatch.setattr(harness, "write_new", failing)
    assert harness.finalize(tmp_path, _phase_ready_result(), harness.Budget(clock=lambda: 0.0)) == 1
    assert b"SECRET_EXCEPTION_PAYLOAD" not in (tmp_path / "result.json").read_bytes()
    refusal = (tmp_path / "finalization-refusal.json").read_bytes()
    assert b"SECRET_EXCEPTION_PAYLOAD" not in refusal
    assert wire.load(refusal)["error_type"] == "OSError"


@pytest.mark.parametrize("bad_input", ("wrong_parameters", "duplicate_parameters", "missing_parameters",
                                     "missing_parameter_env", "parameter_prefix", "missing_lock",
                                     "wrong_lock", "missing_plugin", "unobtained_final_source"))
def test_early_acquisition_refusal_is_structured_preserves_received_bytes_and_starts_no_tests(
        tmp_path, monkeypatch, bad_input):
    source, out, work = (tmp_path / name for name in ("source", "out", "work"))
    source.mkdir()
    (source / "workloads/m12_adjudication_verify").mkdir(parents=True)
    lock_path = source / "uv.lock"
    lock_path.write_bytes((ROOT / "uv.lock").read_bytes())
    plugin_path = source / "workloads/m12_adjudication_verify/pytest_partition.py"
    plugin_path.write_bytes(b"# synthetic, never imported\n")
    parameter_path = tmp_path / "parameters.json"
    raw_parameters = b'{"shard":"0"}'
    if bad_input == "wrong_parameters":
        raw_parameters = b'{"shard":"SECRET_NOT_IN_EXCEPTION"}'
    elif bad_input == "duplicate_parameters":
        raw_parameters = b'{"SECRET_NOT_IN_EXCEPTION":"a","SECRET_NOT_IN_EXCEPTION":"b"}'
    elif bad_input == "parameter_prefix":
        raw_parameters = b"p" * 5000
    if bad_input not in {"missing_parameters", "missing_parameter_env"}:
        parameter_path.write_bytes(raw_parameters)
    if bad_input in {"missing_lock", "unobtained_final_source"}:
        lock_path.unlink()
    elif bad_input == "wrong_lock":
        lock_path.write_bytes(b"not the original lock\n")
    elif bad_input == "missing_plugin":
        plugin_path.unlink()
    monkeypatch.setattr(harness, "ROOT", source)
    monkeypatch.setattr(harness.sys, "platform", "win32")
    monkeypatch.setattr(harness.platform, "node", lambda: harness.HOST)
    monkeypatch.setattr(harness.platform, "machine", lambda: "AMD64")
    monkeypatch.setattr(harness.platform, "platform", lambda: "synthetic-early-refusal")
    values = {"EC_WORKLOAD_SOURCE": str(source), "EC_WORKLOAD_OUT": str(out),
              "EC_WORKLOAD_WORK": str(work), "EC_WORKLOAD_SHA": SOURCE,
              "EC_WORKLOAD_PARAMETERS": str(parameter_path), "COMPUTERNAME": harness.HOST,
              "EC_WORKLOAD_REPOSITORY": "taipei49314/smallestlie",
              "EC_WORKLOAD_NAME": harness.WORKLOAD, "EC_WORKLOAD_MODE": "single"}
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    if bad_input == "missing_parameter_env":
        monkeypatch.delenv("EC_WORKLOAD_PARAMETERS")
    monkeypatch.delenv("EC_WORKLOAD_CACHE", raising=False)
    calls = []
    class SourceOnlyRunner:
        def __init__(self, root, result_out, env, budget, output=None):
            self.out = result_out
            self.steps = []
        def run(self, name, command, cap, *, final=False):
            calls.append(name)
            assert command[0] == "git", "early refusal must not start setup/pytest"
            if name == "final-source" and bad_input == "unobtained_final_source":
                raise OSError("SECRET_NOT_IN_EXCEPTION")
            raw = (SOURCE + "\n").encode() if name.endswith("-source") else b""
            (self.out / (name + ".stdout")).write_bytes(raw)
            (self.out / (name + ".stderr")).write_bytes(b"")
            self.steps.append({"name": name, "exit_code": 0, "started": True, "timed_out": False})
            return 0
    monkeypatch.setattr(harness, "Runner", SourceOnlyRunner)
    assert harness.main() == 1
    result_raw = (out / "result.json").read_bytes()
    result = wire.load(result_raw)
    assert result["early_refusal"] is True
    assert result["partition_complete"] is False
    assert result["phase_checks_complete"] is False
    if bad_input == "unobtained_final_source":
        assert result["source_observations"]["final"]["sha"] is None
        assert result["source_observations"]["final"]["status_exit"] is None
        assert calls == ["initial-source", "initial-status", "final-source"]
    else:
        assert result["source_observations"]["final"]["sha"] == SOURCE
        assert calls == ["initial-source", "initial-status", "final-source", "final-status"]
    assert b"SECRET_NOT_IN_EXCEPTION" not in result_raw
    assert b"SECRET_NOT_IN_EXCEPTION" not in (out / "SUMMARY.md").read_bytes()
    if bad_input in {"missing_parameters", "missing_parameter_env"}:
        assert result["parameters_sha256"] is None
        assert result["acquisitions"]["parameters"]["received_sha256"] is None
        assert not (out / "parameters.raw.json").exists()
    elif bad_input == "parameter_prefix":
        assert (out / "parameters.raw.json").read_bytes() == raw_parameters[:4097]
        assert result["parameters_sha256"] is None
        assert result["acquisitions"]["parameters"]["status"] == "RECEIVED_PREFIX"
        assert result["acquisitions"]["parameters"]["sha256"] is None
    else:
        assert (out / "parameters.raw.json").read_bytes() == raw_parameters
    if bad_input in {"missing_lock", "missing_plugin"}:
        name = "lock" if bad_input == "missing_lock" else "plugin"
        assert result["acquisitions"][name]["received_sha256"] is None
        assert result["acquisitions"][name]["sha256"] is None
