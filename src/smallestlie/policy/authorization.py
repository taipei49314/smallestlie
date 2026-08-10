"""Authorization objects and validation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from smallestlie.policy.path_guard import PathGuard, PathGuardError


class AuthorizationError(Exception):
    """Authorization failed; campaign must BLOCKED_BY_POLICY."""


ALLOWED_MODES = {
    "owned_local_repo",
    "synthetic_fixture",
    "explicit_allowlist",
    "disposable_clone",
}

ALLOWED_FAMILIES = {
    "evidence",
    "execution",
    "semantic",
    "path",
    "freshness",
    "workflow",
    "authority",
    "composition",
    "config",
    "verifier",
    "projection",
}

FORBIDDEN_TARGET_PREFIXES = (
    "http://",
    "https://",
    "git@",
    "ssh://",
    "ftp://",
)


@dataclass
class Authorization:
    mode: str
    owner: str
    target_path: str
    disposable_clone_required: bool = True
    network: str = "denied"
    expires_at: str | None = None
    allowed_attack_families: list[str] = field(default_factory=list)
    allowlisted_roots: list[str] = field(default_factory=list)
    schema_version: str = "smallestlie.authorization/v1"
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def digest(self) -> str:
        payload = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_authorization(path: str | Path) -> Authorization:
    p = Path(path)
    if not p.is_file():
        raise AuthorizationError(f"authorization file not found: {p}")
    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise AuthorizationError("authorization must be a mapping")
    # Support nested `authorization:` key or flat document.
    data = raw.get("authorization", raw)
    if not isinstance(data, dict):
        raise AuthorizationError("authorization body must be a mapping")
    try:
        return Authorization(
            mode=str(data["mode"]),
            owner=str(data["owner"]),
            target_path=str(data["target_path"]),
            disposable_clone_required=bool(data.get("disposable_clone_required", True)),
            network=str(data.get("network", "denied")),
            expires_at=data.get("expires_at"),
            allowed_attack_families=list(data.get("allowed_attack_families") or []),
            allowlisted_roots=list(data.get("allowlisted_roots") or []),
            schema_version=str(data.get("schema_version", "smallestlie.authorization/v1")),
            notes=str(data.get("notes", "")),
        )
    except KeyError as exc:
        raise AuthorizationError(f"missing authorization field: {exc}") from exc


def _parse_expiry(value: str) -> datetime:
    # Accept ISO-8601 with optional Z.
    v = value.strip()
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    dt = datetime.fromisoformat(v)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def validate_authorization(
    auth: Authorization,
    *,
    now: datetime | None = None,
    require_existing_target: bool = True,
) -> Path:
    """Validate auth object. Returns canonical target path on success."""
    if auth.mode not in ALLOWED_MODES:
        raise AuthorizationError(f"unsupported authorization mode: {auth.mode}")
    if not auth.owner:
        raise AuthorizationError("owner is required")
    if not auth.target_path:
        raise AuthorizationError("target_path is required")

    target_raw = auth.target_path.strip()
    lower = target_raw.lower()
    for prefix in FORBIDDEN_TARGET_PREFIXES:
        if lower.startswith(prefix):
            raise AuthorizationError(f"remote targets are forbidden: {target_raw}")

    # Reject bare roots / home.
    forbidden_names = {"/", "\\", "~"}
    if target_raw in forbidden_names:
        raise AuthorizationError(f"forbidden target path: {target_raw}")

    try:
        target = PathGuard.canonicalize(target_raw)
    except PathGuardError as exc:
        raise AuthorizationError(str(exc)) from exc

    if require_existing_target and not target.exists():
        raise AuthorizationError(f"target does not exist: {target}")

    # Disallow using filesystem root as target.
    if target.parent == target:
        raise AuthorizationError(f"refusing filesystem root as target: {target}")

    if auth.network != "denied":
        raise AuthorizationError(
            f"network policy must be 'denied' in M0–M1 (got {auth.network!r})"
        )

    if not auth.disposable_clone_required and auth.mode != "synthetic_fixture":
        raise AuthorizationError("disposable_clone_required must be true")

    families = set(auth.allowed_attack_families)
    if not families:
        raise AuthorizationError("allowed_attack_families must be non-empty")
    unknown = families - ALLOWED_FAMILIES
    if unknown:
        raise AuthorizationError(f"unknown attack families: {sorted(unknown)}")

    if auth.expires_at:
        expiry = _parse_expiry(str(auth.expires_at))
        current = now or datetime.now(timezone.utc)
        if current > expiry:
            raise AuthorizationError(f"authorization expired at {auth.expires_at}")

    # Optional root allowlist (explicit_allowlist / owned_local_repo).
    if auth.allowlisted_roots:
        ok = False
        for root in auth.allowlisted_roots:
            try:
                guard = PathGuard(root)
                guard.ensure_inside(target, label="target")
                ok = True
                break
            except (PathGuardError, OSError):
                continue
        if not ok:
            raise AuthorizationError(
                f"target not under any allowlisted root: {target}"
            )

    return target


def default_fixture_authorization(target: Path, *, owner: str = "nelson") -> Authorization:
    """Build synthetic-fixture authorization for shipped fixtures."""
    return Authorization(
        mode="synthetic_fixture",
        owner=owner,
        target_path=str(PathGuard.canonicalize(target)),
        disposable_clone_required=True,
        network="denied",
        expires_at="2099-12-31T23:59:59+00:00",
        allowed_attack_families=sorted(ALLOWED_FAMILIES),
        notes="auto-generated for synthetic fixture campaign",
    )
