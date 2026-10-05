"""Audit the shipped 0.6.0 amendment with synthetic authority; never run arms.

This contract proves no human approval, source adoption or formal W3 result.
The temporary Git history and authority below exist only for this unit test.
"""

import hashlib
import json
from pathlib import Path
import subprocess

from smallestlie.campaign.preregistration import (
    PreregistrationApproval, RunRequest, canonical_digest, prepare_run,
)

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = "campaigns/checkwash-wave-3/manifest-v0.6.0.json"


class SyntheticAuditAuthority:
    def verify(self, request):
        return PreregistrationApproval("synthetic-amendment-audit-only", request.authorization_ref,
            request.phase1_commit, request.manifest_sha256, canonical_digest(request.payload()))


def test_shipped_amendment_closes_all_inputs_without_running_cases(tmp_path):
    manifest_raw = (ROOT / MANIFEST).read_bytes()
    manifest = json.loads(manifest_raw)
    for ref in (*manifest["assets"], MANIFEST):
        target = tmp_path / ref
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / ref).read_bytes())

    def git(*args):
        return subprocess.run(["git", "-C", str(tmp_path), "-c", "core.hooksPath=NUL",
            "-c", "core.autocrlf=false", "-c", "commit.gpgsign=false", *args],
            check=True, capture_output=True, timeout=60).stdout.decode().strip()

    git("init", "-q")
    git("add", "--all")
    git("-c", "user.name=Synthetic source audit", "-c", "user.email=audit@example.invalid",
        "commit", "-qm", "Synthetic only; no real Phase1 approval")
    source = git("rev-parse", "HEAD")
    request = RunRequest("checkwash-wave-3", "synthetic-amendment-audit", "synthetic-audit",
        source, source, hashlib.sha256(manifest_raw).hexdigest(), "synthetic-authority-only")
    prepared = prepare_run(tmp_path, MANIFEST, request, authority=SyntheticAuditAuthority())
    lock = prepared.lock()
    assert lock["engine"]["version"] == "0.6.0"
    assert [(case["case_id"], case["preregistered_class"], case["twin_case_id"])
            for case in lock["cases"]] == [
        ("CW-W3-D1", "DEF", "CW-W3-D1-CTL"), ("CW-W3-D1-CTL", "CTL", None),
        ("CW-W3-D2", "DEF", "CW-W3-D2-CTL"), ("CW-W3-D2-CTL", "CTL", None),
        ("CW-W3-B1", "BND", "CW-W3-B1-CTL"), ("CW-W3-B1-CTL", "CTL", None),
    ]
    assert {ref for ref, raw in prepared.assets} == set(manifest["assets"])
