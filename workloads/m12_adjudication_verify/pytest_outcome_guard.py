"""Raw final pytest phase outcomes for the unchanged focused diagnostic paths.

SOURCE_ONLY / NOT_RUN. In particular, non-strict xpass must not hide behind an
exit-zero JUnit without skipped/failure children. Full occurrence coverage uses
the separate partition plugin, not this diagnostic guard.
"""

from pathlib import Path

import pytest

from workloads.m12_adjudication_verify.protocol import canonical
from workloads.m12_adjudication_verify.output_bound import OutputBudget, bind_junit, close_preserving_primary

_state = None


def pytest_addoption(parser):
    parser.addoption("--sl-outcome-evidence")


@pytest.hookimpl(trylast=True)
def pytest_configure(config):
    global _state
    prefix = config.getoption("sl_outcome_evidence")
    if not prefix:
        raise pytest.UsageError("focused outcome evidence path required")
    output = OutputBudget.child()
    _state = {"prefix": Path(prefix), "stream": output.open(Path(prefix + ".events.jsonl")), "output": output}
    bind_junit(config, output)


def _write(record):
    _state["stream"].write(canonical(record))
    _state["stream"].flush()


def pytest_runtest_logreport(report):
    _write({"event": "phase", "nodeid": report.nodeid, "when": report.when,
            "outcome": report.outcome, "wasxfail": hasattr(report, "wasxfail")})


@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus):
    terminal = {"schema_version": 1, "plugin_loaded": True, "scope": "focused_diagnostic",
                "tests_collected": session.testscollected, "exitstatus": int(exitstatus)}
    try:
        _write({"event": "session_finish", **terminal})
        _state["output"].write_new(Path(str(_state["prefix"]) + ".session.json"), canonical(terminal))
    finally:
        close_preserving_primary(_state["stream"])


def pytest_unconfigure(config):
    global _state
    if _state is not None and not _state["stream"].closed:
        close_preserving_primary(_state["stream"])
    _state = None
