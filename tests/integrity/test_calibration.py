"""Calibration integrity: mutation relevance and 3/3 replay stability."""

from __future__ import annotations

from pathlib import Path

import pytest

from smallestlie.adapters.greenwash import GreenwashAdapter
from smallestlie.attacks.primitives import apply_mutations
from smallestlie.baseline.capture import capture_baseline
from smallestlie.campaign.runner import _replay_false_accept, _run_mutant_once
from smallestlie.models import ComparisonResult
from smallestlie.oracle.base import evaluate_oracle
from smallestlie.policy.authorization import default_fixture_authorization
from smallestlie.sandbox.executor import SandboxExecutor
from smallestlie.sandbox.workspace import DisposableWorkspace
from smallestlie.verdict.compare import compare


ROOT = Path(__file__).resolve().parents[2]


def _baseline(target: Path):
    adapter = GreenwashAdapter()
    auth = default_fixture_authorization(target)
    return (
        adapter,
        capture_baseline(
            target,
            adapter_name=adapter.name,
            adapter_version=adapter.version,
            authorization_digest=auth.digest(),
        ),
        adapter.command_allowlist(),
    )


def _empty_junit_mutation():
    return {
        "type": "write_text",
        "path": "package/junit/results.xml",
        "content": (
            '<?xml version="1.0"?>\n'
            '<testsuite name="s" tests="0" failures="0" errors="0" skipped="0">\n'
            "</testsuite>\n"
        ),
    }


def test_renamed_mutation_still_false_accepts(tmp_path: Path) -> None:
    """Rename of required report is a relevant mutation (PATH theater)."""
    target = ROOT / "fixtures" / "greenwash_naive"
    adapter, baseline, allowlist = _baseline(target)
    mutations = [
        {
            "type": "rename_path",
            "from": "package/ci-summary.json",
            "to": "package/ci-summary.json.bak",
        }
    ]
    from smallestlie.attacks.schema import AttackSpec

    attack = AttackSpec(
        attack_id="CAL-RENAME",
        name="rename",
        family="path",
        purpose="cal",
        mutations=mutations,
        execute={"command_ref": "run_greenwash_audit"},
        oracle={"type": "theater_presence"},
        false_accept_condition={"target_accepted": True, "oracle_valid": False},
    )
    one = _run_mutant_once(
        mutations=mutations,
        attack=attack,
        target_path=target,
        baseline=baseline,
        adapter=adapter,
        allowlist=allowlist,
    )
    assert one["comparison"]["result"] == ComparisonResult.FALSE_ACCEPT_OBSERVED.value


def test_equivalent_structure_same_classification(tmp_path: Path) -> None:
    """Two equivalent zero-test junit bodies yield the same FA classification."""
    target = ROOT / "fixtures" / "greenwash_naive"
    adapter, baseline, allowlist = _baseline(target)
    from smallestlie.attacks.schema import AttackSpec

    m1 = [
        {
            "type": "write_text",
            "path": "package/junit/results.xml",
            "content": '<?xml version="1.0"?><testsuite tests="0"></testsuite>\n',
        }
    ]
    m2 = [
        {
            "type": "write_text",
            "path": "package/junit/results.xml",
            "content": (
                '<?xml version="1.0" encoding="utf-8"?>\n'
                '<testsuite name="suite" tests="0" failures="0" errors="0" skipped="0">\n'
                "</testsuite>\n"
            ),
        }
    ]
    attack = AttackSpec(
        attack_id="CAL-EQ",
        name="eq",
        family="execution",
        purpose="cal",
        mutations=m1,
        execute={"command_ref": "run_greenwash_audit"},
        oracle={"type": "theater_presence"},
        false_accept_condition={"target_accepted": True, "oracle_valid": False},
    )
    r1 = _run_mutant_once(
        mutations=m1, attack=attack, target_path=target, baseline=baseline, adapter=adapter, allowlist=allowlist
    )
    r2 = _run_mutant_once(
        mutations=m2, attack=attack, target_path=target, baseline=baseline, adapter=adapter, allowlist=allowlist
    )
    assert r1["comparison"]["result"] == r2["comparison"]["result"]
    assert r1["comparison"]["result"] == ComparisonResult.FALSE_ACCEPT_OBSERVED.value


def test_irrelevant_mutation_does_not_create_theater(tmp_path: Path) -> None:
    """Touching an unrelated note file must not invent theater on honest control."""
    target = ROOT / "fixtures" / "greenwash_honest"
    adapter, baseline, allowlist = _baseline(target)
    from smallestlie.attacks.schema import AttackSpec

    mutations = [
        {
            "type": "write_text",
            "path": "package/README_NOTE.txt",
            "content": "irrelevant comment\n",
        }
    ]
    attack = AttackSpec(
        attack_id="CAL-IRREL",
        name="irrel",
        family="projection",
        purpose="cal",
        mutations=mutations,
        execute={"command_ref": "run_greenwash_audit"},
        oracle={"type": "theater_presence"},
        false_accept_condition={"target_accepted": True, "oracle_valid": False},
    )
    one = _run_mutant_once(
        mutations=mutations,
        attack=attack,
        target_path=target,
        baseline=baseline,
        adapter=adapter,
        allowlist=allowlist,
    )
    # Oracle should still see clean world; target accepts => TRUE_ACCEPT
    assert one["oracle_valid"] is True
    assert one["target_accepted"] is True
    assert one["comparison"]["result"] == ComparisonResult.TRUE_ACCEPT_OBSERVED.value


def test_3_of_3_replay_matrix_for_seeded_fa(tmp_path: Path) -> None:
    """Seeded FA on greenwash_naive reproduces 3/3 under pinned mutations."""
    target = ROOT / "fixtures" / "greenwash_naive"
    adapter, baseline, allowlist = _baseline(target)
    from smallestlie.attacks.schema import AttackSpec

    mutations = [_empty_junit_mutation()]
    attack = AttackSpec(
        attack_id="CAL-REPLAY",
        name="replay",
        family="execution",
        purpose="cal",
        mutations=mutations,
        execute={"command_ref": "run_greenwash_audit"},
        oracle={"type": "theater_presence"},
        false_accept_condition={"target_accepted": True, "oracle_valid": False},
    )
    replay = _replay_false_accept(
        attack=attack,
        target_path=target,
        baseline=baseline,
        adapter=adapter,
        allowlist=allowlist,
        attempts=3,
        mutations=mutations,
    )
    assert replay["attempts"] == 3
    assert replay["reproduced"] == 3
    assert replay["stable"] is True
