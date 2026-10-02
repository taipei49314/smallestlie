"""Declarative attack specification loading and validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

from smallestlie.attacks.adjudication import DeclarationError, validate_declarations

V1 = "smallestlie.attack/v1"
V2 = "smallestlie.attack/v2"

ALLOWED_MUTATION_TYPES = {
    "replace_text",
    "structured_set",
    "structured_delete",
    "delete_path",
    "rename_path",
    "duplicate_path",
    "write_text",
    "write_json",
}


class AttackSchemaError(Exception):
    pass


class UniqueKeyLoader(yaml.SafeLoader):
    """Reject ambiguous YAML, including nested duplicate keys."""


def _unique_mapping(loader: UniqueKeyLoader, node: Any, deep: bool = False) -> dict:
    loader.flatten_mapping(node)
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise AttackSchemaError("unhashable YAML mapping key") from exc
        if duplicate:
            raise AttackSchemaError(f"duplicate YAML key: {key!r}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping)


def load_mapping_bytes(data: bytes, *, source_path: str) -> dict[str, Any]:
    """Parse the same bytes a caller has authenticated, without reopening a file."""
    try:
        raw = yaml.load(data.decode("utf-8"), Loader=UniqueKeyLoader)
    except (yaml.YAMLError, AttackSchemaError, UnicodeError) as exc:
        raise AttackSchemaError(f"invalid YAML in {source_path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise AttackSchemaError(f"spec must be mapping: {source_path}")
    return raw


def load_mapping(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    return load_mapping_bytes(p.read_bytes(), source_path=str(p))


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
    adjudication: dict[str, Any] | None = None
    runner_protocol: dict[str, Any] | None = None
    source_path: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        result = deepcopy(self.raw) if self.raw else {
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
        if self.schema_version == V2:
            # Serialize the actual declaration, not a stale copy in raw.
            result.update(schema_version=V2, attack_id=self.attack_id, name=self.name,
                          family=self.family, purpose=self.purpose,
                          mutations=deepcopy(self.mutations),
                          execute=deepcopy(self.execute), oracle=deepcopy(self.oracle),
                          false_accept_condition=deepcopy(self.false_accept_condition),
                          adjudication=deepcopy(self.adjudication),
                          runner_protocol=deepcopy(self.runner_protocol))
            for key in ("authorization_requirements", "applies_when", "preconditions",
                        "minimization", "regression_export"):
                if key in result or getattr(self, key):
                    result[key] = deepcopy(getattr(self, key))
        return result


def load_attack_spec(path: str | Path) -> AttackSpec:
    return parse_attack_spec(load_mapping(path), source_path=str(path))


def parse_attack_spec(raw: dict[str, Any], *, source_path: str | None = None) -> AttackSpec:
    if not isinstance(raw, dict):
        raise AttackSchemaError("attack spec must be a mapping")
    version = raw.get("schema_version", V1)
    if not isinstance(version, str) or version not in {V1, V2}:
        raise AttackSchemaError(f"unsupported attack schema: {version!r}")
    if version == V1 and {"adjudication", "runner_protocol", "runner_evidence"} & raw.keys():
        raise AttackSchemaError("v2 declarations cannot be silently interpreted as v1")
    raw = deepcopy(raw)
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

    adjudication = protocol = None
    if version == V2:
        known = set(required) | {"schema_version", "authorization_requirements", "applies_when",
                                "preconditions", "minimization", "regression_export",
                                "adjudication", "runner_protocol"}
        if raw.keys() - known:
            raise AttackSchemaError(f"unknown v2 fields: {sorted(map(str, raw.keys() - known))}")
        for key in ("attack_id", "name", "family", "purpose"):
            if not isinstance(raw[key], str) or not raw[key].strip():
                raise AttackSchemaError(f"{key} must be a nonempty string")
        if raw["family"] == "composition":
            raise AttackSchemaError("v2 composition is not supported")
        for key in ("oracle", "false_accept_condition", "authorization_requirements",
                    "applies_when", "minimization", "regression_export"):
            if key in raw and not isinstance(raw[key], dict):
                raise AttackSchemaError(f"{key} must be a mapping")
        if "preconditions" in raw and not isinstance(raw["preconditions"], list):
            raise AttackSchemaError("preconditions must be a list")
        try:
            adjudication, protocol = validate_declarations(raw, raw["attack_id"])
        except DeclarationError as exc:
            raise AttackSchemaError(str(exc)) from exc

    mutations = raw["mutations"]
    if not isinstance(mutations, list):
        raise AttackSchemaError("mutations must be a list")
    if version == V2 and not mutations:
        raise AttackSchemaError("v2 mutations must not be empty")
    for i, m in enumerate(mutations):
        if not isinstance(m, dict):
            raise AttackSchemaError(f"mutation[{i}] must be a mapping")
        mtype = m.get("type")
        if not isinstance(mtype, str) or mtype not in ALLOWED_MUTATION_TYPES:
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
    if version == V2:
        if not isinstance(execute["command_ref"], str) or not execute["command_ref"].strip():
            raise AttackSchemaError("execute.command_ref must be a nonempty string")
        timeout = execute.get("timeout_seconds", 60)
        if type(timeout) is not int or timeout <= 0:
            raise AttackSchemaError("execute.timeout_seconds must be a positive integer")
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
        schema_version=version,
        authorization_requirements=dict(raw.get("authorization_requirements") or {}),
        applies_when=dict(raw.get("applies_when") or {}),
        preconditions=list(raw.get("preconditions") or []),
        minimization=dict(raw.get("minimization") or {}),
        regression_export=dict(raw.get("regression_export") or {}),
        source_path=source_path,
        adjudication=adjudication,
        runner_protocol=protocol,
        raw=deepcopy(raw),
    )
