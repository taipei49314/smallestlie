"""Authorization policy tests."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from smallestlie.policy.authorization import (
    Authorization,
    AuthorizationError,
    load_authorization,
    validate_authorization,
)


def test_remote_url_blocked(tmp_path: Path) -> None:
    auth = Authorization(
        mode="owned_local_repo",
        owner="nelson",
        target_path="https://example.com/repo.git",
        allowed_attack_families=["evidence"],
    )
    with pytest.raises(AuthorizationError, match="remote"):
        validate_authorization(auth, require_existing_target=False)


def test_expired_authorization_blocked(tmp_path: Path) -> None:
    auth = Authorization(
        mode="synthetic_fixture",
        owner="nelson",
        target_path=str(tmp_path),
        expires_at="2020-01-01T00:00:00+00:00",
        allowed_attack_families=["evidence"],
    )
    with pytest.raises(AuthorizationError, match="expired"):
        validate_authorization(auth, now=datetime(2026, 1, 1, tzinfo=timezone.utc))


def test_network_must_be_denied(tmp_path: Path) -> None:
    auth = Authorization(
        mode="synthetic_fixture",
        owner="nelson",
        target_path=str(tmp_path),
        network="allowed",
        allowed_attack_families=["evidence"],
    )
    with pytest.raises(AuthorizationError, match="network"):
        validate_authorization(auth)


def test_load_and_validate_fixture_auth(tmp_path: Path) -> None:
    doc = {
        "authorization": {
            "mode": "synthetic_fixture",
            "owner": "nelson",
            "target_path": str(tmp_path),
            "disposable_clone_required": True,
            "network": "denied",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "allowed_attack_families": ["evidence", "execution"],
        }
    }
    path = tmp_path / "auth.yaml"
    # write beside target — use parent
    path = tmp_path.parent / "auth-test.yaml"
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")
    auth = load_authorization(path)
    target = validate_authorization(auth)
    assert target == tmp_path.resolve()
    path.unlink(missing_ok=True)
