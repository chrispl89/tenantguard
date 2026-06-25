"""HTTP client for executing authorization checks."""

from __future__ import annotations

import time
from urllib.parse import urlparse

import httpx

from tenantguard.config import CheckConfig, TenantGuardConfig
from tenantguard.models import RuntimeContext
from tenantguard.results import RequestSnapshot, ResponseSnapshot
from tenantguard.safety import REDACTED_MARKER, redact_header_value, redact_secrets

BODY_SNIPPET_LIMIT = 1000


class ClientError(Exception):
    """Raised when a request cannot be built or executed safely."""


def validate_relative_path(path: str) -> str:
    """Ensure the request path is relative and normalized."""
    stripped = path.strip()
    parsed = urlparse(stripped)
    if parsed.scheme or parsed.netloc:
        msg = "Request path must be a relative path, not an absolute URL."
        raise ClientError(msg)
    if not stripped:
        msg = "Request path must not be empty."
        raise ClientError(msg)
    return stripped if stripped.startswith("/") else f"/{stripped}"


def build_request_url(base_url: str, path: str) -> str:
    """Combine base URL and relative path without allowing host override."""
    normalized_path = validate_relative_path(path)
    return f"{base_url.rstrip('/')}{normalized_path}"


def sanitize_headers(
    headers: dict[str, str],
    *,
    secrets: list[str] | None = None,
) -> dict[str, str]:
    """Return headers safe for reports and terminal output."""
    secret_list = secrets or []
    return {
        key: redact_header_value(key, value, secret_list)
        for key, value in headers.items()
    }


def build_auth_snapshot_header(
    auth_type: str,
    cookie_name: str | None,
) -> dict[str, str]:
    """Build redacted auth headers for request snapshots."""
    if auth_type == "cookie" and cookie_name:
        return {"Cookie": f"{cookie_name}={REDACTED_MARKER}"}
    if auth_type == "bearer":
        return {"Authorization": REDACTED_MARKER}
    return {}


def make_body_snippet(body: str, secrets: list[str]) -> str:
    """Truncate and redact a response body snippet."""
    snippet = body[:BODY_SNIPPET_LIMIT]
    return redact_secrets(snippet, secrets)


class TenantGuardHttpClient:
    """Synchronous HTTP client for TenantGuard checks."""

    def __init__(
        self,
        *,
        base_url: str,
        timeout: float,
        verify_ssl: bool,
        default_headers: dict[str, str],
    ) -> None:
        self._base_url = base_url
        self._timeout = timeout
        self._verify_ssl = verify_ssl
        self._default_headers = default_headers

    def execute(
        self,
        check: CheckConfig,
        runtime: RuntimeContext,
        config: TenantGuardConfig,
        *,
        rendered_path: str,
        secrets: list[str],
    ) -> tuple[RequestSnapshot, ResponseSnapshot, httpx.Response]:
        """Execute a single check and return snapshots plus the raw response."""
        actor_config = config.actors[check.actor]
        secret = runtime.actor_tokens.get(check.actor)
        if secret is None:
            msg = f"No token resolved for actor {check.actor!r}"
            raise ClientError(msg)

        url = build_request_url(self._base_url, rendered_path)
        headers = dict(self._default_headers)
        headers.update(check.request.headers)

        request_cookies: dict[str, str] | None = None
        if actor_config.auth.type == "cookie":
            cookie_name = actor_config.auth.cookie_name
            if cookie_name is None:
                msg = f"cookie_name is required for cookie auth on actor {check.actor!r}"
                raise ClientError(msg)
            headers.pop("Authorization", None)
            headers.pop("Cookie", None)
            request_cookies = {cookie_name: secret}
        else:
            headers["Authorization"] = f"Bearer {secret}"

        snapshot_headers = sanitize_headers(headers, secrets=secrets)
        snapshot_headers.update(
            build_auth_snapshot_header(actor_config.auth.type, actor_config.auth.cookie_name)
        )

        request_snapshot = RequestSnapshot(
            method=check.request.method,
            url=url,
            path=validate_relative_path(rendered_path),
            actor=check.actor,
            headers=snapshot_headers,
            json_body=check.request.body_json,
        )

        started = time.perf_counter()
        try:
            if request_cookies is not None:
                client = httpx.Client(
                    timeout=self._timeout,
                    verify=self._verify_ssl,
                    cookies=request_cookies,
                )
            else:
                client = httpx.Client(
                    timeout=self._timeout,
                    verify=self._verify_ssl,
                )
            with client:
                response = client.request(
                    check.request.method,
                    url,
                    headers=headers,
                    json=check.request.body_json,
                )
        except httpx.HTTPError as exc:
            msg = f"HTTP request failed: {exc}"
            raise ClientError(redact_secrets(msg, secrets)) from exc

        elapsed_ms = (time.perf_counter() - started) * 1000
        body_text = response.text
        response_snapshot = ResponseSnapshot(
            status_code=response.status_code,
            headers=dict(response.headers),
            body_snippet=make_body_snippet(body_text, secrets) if body_text else None,
            elapsed_ms=elapsed_ms,
        )
        return request_snapshot, response_snapshot, response
