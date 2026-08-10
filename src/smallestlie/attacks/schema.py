"""Declarative attack specification loading and validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

ALLOWED_MUTATION_TYPES = {
    "replace_text",
    "structured_set",
    "delete_path",
    "rename_path",
    "duplicate_path",
    "write_text",
    "write_json",
}


class AttackSchemaError(Exception):
    pass


@dataclass
class AttackSpec:
    attack_id: str
    name: str
    family: str
    purpose: str
    mutations: list[dict[str, Any]]
    execute: dict[str, Any]
    oracle: dict[str, Any]
    false_accept_condition: dict[str, Any]
    schema_version: str = "smallestlie.attack/v1"
    authorization_requirements: dict[str, Any] = field(default_factory=dict)
    applies_when: dict[str, Any] = field(default_factory=dict)
    preconditions: list[dict[str, Any]] = field(default_factory=list)
    minimization: dict[str, Any] = field(default_factory=dict)
    regression_export: dict[str, Any] = field(default_factory=dict)
    source_path: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return dict(self.raw) if self.raw else {
            "schema_version": self.schema_version,
            "attack_id": self.attack_id,
            "name": self.name,
            "family": self.family,
            "purpose": self.purpose,
            "authorization_requirements": self.authorization_requirements,
            "applies_when": self.applies_when,
            "preconditions": self.preconditions,
            "mutations": self.mutations,
            "execute": self.execute,
            "oracle": self.oracle,
            "false_accept_condition": self.false_accept_condition,
            "minimization": self.minimization,
            "regression_export": self.regression_export,
        }


def load_attack_spec(path: str | Path) -> AttackSpec:
    p = Path(path)
    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise AttackSchemaError(f"attack spec must be mapping: {p}")
    return parse_attack_spec(raw, source_path=str(p))


def parse_attack_spec(raw: dict[str, Any], *, source_path: str | None = None) -> AttackSpec:
    required = [
        "attack_id",
        "name",
        "family",
        "purpose",
        "mutations",
        "execute",
        "oracle",
        "false_accept_condition",
    ]
    for key in required:
        if key not in raw:
            raise AttackSchemaError(f"missing field {key!r} in {source_path or 'spec'}")

    mutations = raw["mutations"]
    if not isinstance(mutations, list):
        raise AttackSchemaError("mutations must be a list")
    for i, m in enumerate(mutations):
        if not isinstance(m, dict):
            raise AttackSchemaError(f"mutation[{i}] must be a mapping")
        mtype = m.get("type")
        if mtype not in ALLOWED_MUTATION_TYPES:
            raise AttackSchemaError(
                f"mutation[{i}] type {mtype!r} not allowlisted; "
                f"allowed={sorted(ALLOWED_MUTATION_TYPES)}"
            )
        # No arbitrary shell/command fields on mutations.
        if "command" in m or "shell" in m or "argv" in m:
            raise AttackSchemaError(
                f"mutation[{i}] must not contain command/shell/argv"
            )

    execute = raw["execute"]
    if not isinstance(execute, dict):
        raise AttackSchemaError("execute must be a mapping")
    if "command_ref" not in execute:
        raise AttackSchemaError("execute.command_ref is required")
    if "command" in execute or "shell" in execute or "argv" in execute:
        raise AttackSchemaError(
            "execute must use command_ref only; raw command/shell/argv forbidden"
        )

    return AttackSpec(
        attack_id=str(raw["attack_id"]),
        name=str(raw["name"]),
        family=str(raw["family"]),
        purpose=str(raw["purpose"]),
        mutations=list(mutations),
        execute=dict(execute),
        oracle=dict(raw["oracle"]),
        false_accept_condition=dict(raw["false_accept_condition"]),
        schema_version=str(raw.get("schema_version", "smallestlie.attack/v1")),
        authorization_requirements=dict(raw.get("authorization_requirements") or {}),
        applies_when=dict(raw.get("applies_when") or {}),
        preconditions=list(raw.get("preconditions") or []),
        minimization=dict(raw.get("minimization") or {}),
        regression_export=dict(raw.get("regression_export") or {}),
        source_path=source_path,
        raw=dict(raw),
    )
