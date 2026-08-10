"""Actor authority oracle."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml


def evaluate(workspace: Path) -> dict[str, Any]:
    policy: dict[str, Any] = {}
    for rel in ("gate_policy.yaml", "config/gate_policy.yaml"):
        p = workspace / rel
        if p.is_file():
            raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            if isinstance(raw, dict):
                policy = raw
            break

    allowed = list(policy.get("allowed_approvers") or ["alice-release"])
    require_approval = policy.get("require_approval")
    # Fail-closed interpretation for oracle: missing require_approval => required
    approval_required = True if require_approval is None else bool(require_approval)

    approval_path = workspace / "authority" / "approval.json"
    approver = None
    if approval_path.is_file():
        try:
            data = json.loads(approval_path.read_text(encoding="utf-8"))
            approver = data.get("approver")
        except json.JSONDecodeError:
            approver = None

    # Actor identity authorization is independent of whether policy currently
    # enforces approval: an allowlisted actor is authorized; others are not.
    on_allowlist = approver is not None and str(approver) in set(allowed)
    # Completion may skip approval only when policy explicitly disables it AND
    # no approval object is present. If an approval object exists, actor must
    # be allowlisted.
    if approval_path.is_file():
        authorized = on_allowlist
    else:
        authorized = (not approval_required) if "require_approval" in policy else False

    return {
        "facts": {
            "approver": approver,
            "allowed_approvers": allowed,
            "require_approval_field_present": "require_approval" in policy,
            "approval_required": approval_required,
            "approver_on_allowlist": bool(on_allowlist),
            "approver_authorized": bool(authorized),
        }
    }
