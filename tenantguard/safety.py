"""Safety guards for authorized testing scope."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from tenantguard.config import WRITE_METHODS, TenantGuardConfig

PUBLIC_TARGET_MESSAGE = (
    "Public target detected. TenantGuard is intended only for applications you "
    "own, maintain, or are explicitly authorized to test. Re-run with "
    "--confirm-authorized-scope only if you have permission."
)

WRITE_METHOD_BLOCKED_MESSAGE = (
    "Write method checks are disabled. Set safety.allow_write_methods to true "
    "to enable POST, PUT, PATCH, and DELETE checks."
)


class SafetyError(Exception):
    """Raised when a safety guard blocks execution."""


def parse_target_host(base_url: str) -> str:
    """Extract the host from a base URL without performing DNS lookups."""
    parsed = urlparse(base_url)
    host = parsed.hostname
    if host is None:
        msg = f"Invalid target URL: missing host in {base_url!r}"
        raise SafetyError(msg)
    return host


def _strip_ipv6_brackets(host: str) -> str:
    if host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    return host


def is_local_or_private_host(base_url: str) -> bool:
    """Return True for loopback, RFC1918, or hostname localhost."""
    host = _strip_ipv6_brackets(parse_target_host(base_url))
    if host.lower() == "localhost":
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_loopback or address.is_private


def is_public_target(base_url: str) -> bool:
    """Return True when the target requires explicit authorization confirmation."""
    return not is_local_or_private_host(base_url)


def check_target_scope(config: TenantGuardConfig, *, confirm_authorized_scope: bool) -> None:
    """Block public targets unless the user explicitly confirms authorization."""
    if is_public_target(config.target.base_url) and not confirm_authorized_scope:
        raise SafetyError(PUBLIC_TARGET_MESSAGE)


def check_write_methods(config: TenantGuardConfig) -> None:
    """Reject write-method checks when writes are disabled in safety settings."""
    if config.safety.allow_write_methods:
        return
    blocked = [
        check.id
        for check in config.checks
        if check.request.method in WRITE_METHODS
    ]
    if blocked:
        ids = ", ".join(blocked)
        msg = f"{WRITE_METHOD_BLOCKED_MESSAGE} Blocked checks: {ids}"
        raise SafetyError(msg)


REDACTED_MARKER = "[REDACTED]"


def redact_secrets(value: str, secrets: list[str]) -> str:
    """Replace known secret values with a redaction marker."""
    redacted = value
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, "<redacted>")
    return redacted


def redact_header_value(name: str, value: str, secrets: list[str]) -> str:
    """Return a header value safe for snapshots, reports, and terminal output."""
    lowered = name.lower()
    if lowered == "authorization":
        return REDACTED_MARKER
    if lowered == "cookie":
        for secret in secrets:
            if secret and secret in value:
                return REDACTED_MARKER
        return value
    return redact_secrets(value, secrets)
