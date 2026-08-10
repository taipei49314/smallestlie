"""Network policy — denied by default in M0–M1."""

from __future__ import annotations

from dataclasses import dataclass


class NetworkPolicyError(Exception):
    pass


@dataclass(frozen=True)
class NetworkPolicy:
    mode: str = "denied"

    def __post_init__(self) -> None:
        if self.mode != "denied":
            raise NetworkPolicyError(
                f"only 'denied' network policy is supported (got {self.mode!r})"
            )

    def assert_denied(self) -> None:
        if self.mode != "denied":
            raise NetworkPolicyError("network is not denied")

    def scrub_proxy_env(self, env: dict[str, str]) -> dict[str, str]:
        """Remove proxy and network-related env vars."""
        blocked_keys = {
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "http_proxy",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
            "NO_PROXY",
            "no_proxy",
            "FTP_PROXY",
            "ftp_proxy",
        }
        return {k: v for k, v in env.items() if k not in blocked_keys}
