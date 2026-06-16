"""
core/scope.py

Authorization & blast-radius controls. This runs BEFORE any agent touches
the target. Active testing against a host you don't own is illegal in most
jurisdictions, so the tool refuses to start unless the operator confirms
authorization, and it caps how hard it hits the target.

Controls:
- Authorization gate: explicit consent required (flag or interactive y/N).
- Host allowlist: optional --allow-host restriction.
- Throttle: minimum delay between active requests.
- Budget: hard cap on total active requests sent.
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse


class ScopeError(Exception):
    """Raised when an action would violate the configured scope."""


@dataclass
class ScopePolicy:
    authorized: bool = False           # operator confirmed they may test the target
    allowed_hosts: list[str] = field(default_factory=list)  # empty = only target host
    throttle_seconds: float = 0.2      # min delay between active requests
    max_active_requests: int = 60      # hard budget for the whole run

    # --- runtime counters ---
    _sent: int = 0
    _last_request_ts: float = 0.0

    def require_authorization(self, target_url: str, interactive: bool = True) -> None:
        """
        Block the run unless the operator has confirmed authorization.
        `authorized=True` (set via --authorized) skips the prompt for CI/automation.
        """
        host = urlparse(target_url).hostname or target_url
        if self.authorized:
            return
        if not interactive or not sys.stdin.isatty():
            raise ScopeError(
                "Authorization not confirmed. Re-run with --authorized to confirm "
                f"you have written permission to test {host}."
            )
        print(
            "\n⚠️  ACTIVE SECURITY TESTING\n"
            f"   Target: {host}\n"
            "   Only proceed if you OWN this system or have WRITTEN permission to test it.\n"
        )
        answer = input("   Type 'yes' to confirm authorization: ").strip().lower()
        if answer != "yes":
            raise ScopeError("Authorization declined by operator. Aborting.")
        self.authorized = True

    def assert_in_scope(self, url: str, target_url: str) -> None:
        """Ensure `url` stays on the target host (or an explicitly allowed host)."""
        host = urlparse(url).hostname
        target_host = urlparse(target_url).hostname
        allowed = set(self.allowed_hosts) | ({target_host} if target_host else set())
        if host not in allowed:
            raise ScopeError(f"Out of scope: {host} not in allowed hosts {sorted(allowed)}")

    def before_active_request(self) -> None:
        """Call before every active (state-changing) request. Enforces budget + throttle."""
        if self._sent >= self.max_active_requests:
            raise ScopeError(
                f"Active request budget exhausted ({self.max_active_requests}). "
                "Raise --max-requests if this is intentional."
            )
        elapsed = time.monotonic() - self._last_request_ts
        if elapsed < self.throttle_seconds:
            time.sleep(self.throttle_seconds - elapsed)
        self._sent += 1
        self._last_request_ts = time.monotonic()

    @property
    def requests_sent(self) -> int:
        return self._sent
