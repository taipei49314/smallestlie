"""Strict design declarations; these are hypotheses, never observed results."""

from __future__ import annotations

from copy import deepcopy
from pathlib import PurePosixPath
import re
from typing import Any


class DeclarationError(ValueError):
    pass


def mapping(value: Any, label: str, required: set[str], optional: set[str] | None = None) -> dict:
    if not isinstance(value, dict):
        raise DeclarationError(f"{label} must be a mapping")
    missing = required - value.keys()
    extra = value.keys() - required - (optional or set())
    if missing or extra:
        raise DeclarationError(f"{label}: missing={sorted(missing)}, unknown={sorted(map(str, extra))}")
    return value


def string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DeclarationError(f"{label} must be a nonempty string")
    return value


def choice(value: Any, label: str, allowed: set[str]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise DeclarationError(f"{label} must be one of {sorted(allowed)}")
    return value


def strings(value: Any, label: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        raise DeclarationError(f"{label} must be a {'possibly empty ' if allow_empty else ''}list")
    items = [string(item, label) for item in value]
    if len(set(items)) != len(items):
        raise DeclarationError(f"{label} contains duplicates")
    return items


def relative_path(value: Any, label: str) -> str:
    text = string(value, label)
    path = PurePosixPath(text)
    if (path.is_absolute() or "\\" in text or ":" in text
            or any(part in {"", ".", ".."} for part in text.split("/"))):
        raise DeclarationError(f"{label} must be a confined relative POSIX path")
    return text


def sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise DeclarationError(f"{label} must be a SHA-256 hex digest")
    return value


def validate_declarations(raw: dict, attack_id: str) -> tuple[dict, dict]:
    adj = mapping(raw.get("adjudication"), "adjudication", {
        "preregistered_class", "expected_verifier_outcome", "claim_scope", "residual_mapping",
        "twin", "control_role",
    })
    klass = choice(adj["preregistered_class"], "preregistered_class", {"CTL", "DEF", "BND", "RES"})
    choice(adj["expected_verifier_outcome"], "expected_verifier_outcome",
           {"accept", "block", "visible-warn"})
    scope = mapping(adj["claim_scope"], "claim_scope", {"status", "rationale"})
    choice(scope["status"], "claim_scope.status", {"in_scope", "out_of_scope", "unresolved"})
    string(scope["rationale"], "claim_scope.rationale")
    residual = mapping(adj["residual_mapping"], "residual_mapping",
                       {"status", "row_refs", "rationale"})
    status = choice(residual["status"], "residual_mapping.status",
                    {"matched_residual", "no_match_reviewed", "unresolved"})
    refs = strings(residual["row_refs"], "residual_mapping.row_refs", allow_empty=True)
    string(residual["rationale"], "residual_mapping.rationale")
    if status == "matched_residual" and not refs:
        raise DeclarationError("matched_residual requires row_refs")
    if status == "no_match_reviewed" and refs:
        raise DeclarationError("no_match_reviewed cannot declare matched row_refs")
    if klass == "CTL":
        choice(adj["control_role"], "control_role",
               {"detectable_attack_control", "honest_control", "repair_control"})
    elif adj["control_role"] is not None:
        raise DeclarationError("control_role is only applicable to CTL")
    twin = adj["twin"]
    if klass == "DEF" and twin is None:
        raise DeclarationError("DEF requires a detectable attack twin")
    if twin is not None:
        twin = mapping(twin, "twin", {"case_id", "role", "contrast", "detection"})
        if string(twin["case_id"], "twin.case_id") == attack_id:
            raise DeclarationError("a case cannot be its own twin")
        choice(twin["role"], "twin.role", {"detectable_attack_control"})
        string(twin["contrast"], "twin.contrast")
        detection = mapping(twin["detection"], "twin.detection", {"rule_ids", "paths"})
        strings(detection["rule_ids"], "twin.detection.rule_ids")
        for path in strings(detection["paths"], "twin.detection.paths"):
            relative_path(path, "twin.detection.paths")
    protocol = mapping(raw.get("runner_protocol"), "runner_protocol",
                       {"profile_id", "profile_sha256", "baseline_assertion"})
    string(protocol["profile_id"], "runner_protocol.profile_id")
    sha256(protocol["profile_sha256"], "runner_protocol.profile_sha256")
    string(protocol["baseline_assertion"], "runner_protocol.baseline_assertion")
    return deepcopy(adj), deepcopy(protocol)
