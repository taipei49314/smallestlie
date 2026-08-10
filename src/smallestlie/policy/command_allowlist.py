"""Adapter command allowlist — attack manifests may only reference IDs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class CommandAllowlistError(Exception):
    pass


@dataclass(frozen=True)
class CommandSpec:
    command_id: str
    argv: tuple[str, ...]
    cwd: str = "."
    timeout_seconds: int = 60
    env_allowlist: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "command_id": self.command_id,
            "argv": list(self.argv),
            "cwd": self.cwd,
            "timeout_seconds": self.timeout_seconds,
            "env_allowlist": list(self.env_allowlist),
        }


@dataclass
class CommandAllowlist:
    commands: dict[str, CommandSpec] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, mapping: dict[str, Any]) -> CommandAllowlist:
        commands: dict[str, CommandSpec] = {}
        for cid, body in mapping.items():
            if not isinstance(body, dict):
                raise CommandAllowlistError(f"command {cid} must be a mapping")
            argv = body.get("argv")
            if not isinstance(argv, list) or not argv:
                raise CommandAllowlistError(f"command {cid} requires non-empty argv list")
            # Reject shell metacharacters embedded as single argv blobs with pipes etc.
            for part in argv:
                if not isinstance(part, str):
                    raise CommandAllowlistError(f"command {cid} argv must be strings")
                if any(ch in part for ch in ("|", ";", "&&", "||", "`", "$(", "\n")):
                    raise CommandAllowlistError(
                        f"command {cid} rejects shell metacharacters in argv: {part!r}"
                    )
            commands[cid] = CommandSpec(
                command_id=cid,
                argv=tuple(str(x) for x in argv),
                cwd=str(body.get("cwd", ".")),
                timeout_seconds=int(body.get("timeout_seconds", 60)),
                env_allowlist=tuple(body.get("env_allowlist") or ()),
            )
        return cls(commands=commands)

    def resolve(self, command_ref: str) -> CommandSpec:
        if command_ref not in self.commands:
            raise CommandAllowlistError(
                f"command not on allowlist: {command_ref!r}; "
                f"allowed={sorted(self.commands)}"
            )
        return self.commands[command_ref]

    def ids(self) -> list[str]:
        return sorted(self.commands)
