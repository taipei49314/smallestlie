"""Environment scrubber tests."""

from __future__ import annotations

from smallestlie.sandbox.executor import scrub_environment


def test_strips_dummy_credentials() -> None:
    env = scrub_environment(
        {
            "PATH": "/usr/bin",
            "AWS_SECRET_ACCESS_KEY": "AKIA_DUMMY",
            "GITHUB_TOKEN": "ghp_dummy",
            "NPM_TOKEN": "npm_dummy",
            "SSH_AUTH_SOCK": "/tmp/ssh",
            "HTTP_PROXY": "http://proxy",
            "MY_PASSWORD": "secret",
        }
    )
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "GITHUB_TOKEN" not in env
    assert "NPM_TOKEN" not in env
    assert "SSH_AUTH_SOCK" not in env
    assert "HTTP_PROXY" not in env
    assert "MY_PASSWORD" not in env
    assert env.get("SMALLESTLIE_NETWORK") == "denied"
    assert "PATH" in env
