"""M2 oracle fact-based validity tests."""

from __future__ import annotations

import json
from pathlib import Path

from smallestlie.oracle.base import evaluate_oracle
from smallestlie.oracle import artifact_hash, authority


def test_artifact_hash_mismatch(tmp_path: Path) -> None:
    art = tmp_path / "artifacts"
    art.mkdir()
    (art / "build.bin").write_bytes(b"AAA")
    (art / "manifest.json").write_text(
        json.dumps({"sha256": "deadbeef"}), encoding="utf-8"
    )
    facts = artifact_hash.evaluate(tmp_path)
    assert facts["facts"]["artifact_matches_manifest"] is False
    result = evaluate_oracle(
        tmp_path,
        attack_oracle={"type": "artifact_hash_binding"},
        baseline={"revision": "r1"},
    )
    assert result.valid is False


def test_unauthorized_approver(tmp_path: Path) -> None:
    (tmp_path / "gate_policy.yaml").write_text(
        "require_approval: true\nallowed_approvers:\n  - alice-release\n",
        encoding="utf-8",
    )
    auth = tmp_path / "authority"
    auth.mkdir()
    (auth / "approval.json").write_text(
        json.dumps({"approver": "mallory"}), encoding="utf-8"
    )
    facts = authority.evaluate(tmp_path)
    assert facts["facts"]["approver_authorized"] is False
    result = evaluate_oracle(
        tmp_path,
        attack_oracle={"type": "actor_authority"},
        baseline={"revision": "r1"},
    )
    assert result.valid is False
