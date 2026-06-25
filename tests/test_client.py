"""Tests for the HTTP client."""

from __future__ import annotations

import httpx
import pytest
import respx

from tenantguard.client import (
    ClientError,
    TenantGuardHttpClient,
    build_request_url,
    validate_relative_path,
)
from tenantguard.config import (
    TenantGuardConfig,
)
from tenantguard.models import RuntimeContext


def _config(path: str = "/api/items", method: str = "GET") -> TenantGuardConfig:
    return TenantGuardConfig.model_validate(
        {
            "target": {"base_url": "http://localhost:8000"},
            "actors": {
                "tenant_a_user": {
                    "tenant_id": "tenant_a",
                    "role": "user",
                    "auth": {"type": "bearer", "token_env": "TOKEN"},
                }
            },
            "checks": [
                {
                    "id": "TG-001",
                    "name": "Example",
                    "severity": "high",
                    "actor": "tenant_a_user",
                    "request": {"method": method, "path": path},
                    "expect": {"status_in": [200]},
                }
            ],
        }
    )


def test_build_request_url_from_base_and_relative_path() -> None:
    assert build_request_url("http://localhost:8000", "/api/items") == (
        "http://localhost:8000/api/items"
    )
    assert build_request_url("http://localhost:8000/", "api/items") == (
        "http://localhost:8000/api/items"
    )


def test_rejects_absolute_url_in_request_path() -> None:
    with pytest.raises(ClientError, match="relative path"):
        validate_relative_path("https://evil.example.com/api")


def test_authorization_header_redacted_in_snapshot() -> None:
    config = _config()
    check = config.checks[0]
    runtime = RuntimeContext(actor_tokens={"tenant_a_user": "secret-token-value"})

    with respx.mock:
        respx.get("http://localhost:8000/api/items").mock(
            return_value=httpx.Response(200, text="ok")
        )
        client = TenantGuardHttpClient(
            base_url=config.target.base_url,
            timeout=5.0,
            verify_ssl=True,
            default_headers={"Accept": "application/json"},
        )
        request_snapshot, _, _ = client.execute(
            check,
            runtime,
            config,
            rendered_path="/api/items",
            secrets=["secret-token-value"],
        )

    assert request_snapshot.headers["Authorization"] == "[REDACTED]"
    assert "secret-token-value" not in str(request_snapshot.headers)


def test_execute_adds_config_headers_and_json_body() -> None:
    config = TenantGuardConfig.model_validate(
        {
            "target": {"base_url": "http://localhost:8000"},
            "actors": {
                "tenant_a_user": {
                    "tenant_id": "tenant_a",
                    "role": "user",
                    "auth": {"type": "bearer", "token": "token"},
                }
            },
            "checks": [
                {
                    "id": "TG-001",
                    "name": "Create",
                    "severity": "high",
                    "actor": "tenant_a_user",
                    "request": {
                        "method": "POST",
                        "path": "/api/items",
                        "headers": {"X-Test": "1"},
                        "json": {"name": "demo"},
                    },
                    "expect": {"status_in": [201]},
                }
            ],
            "safety": {"allow_write_methods": True},
        }
    )
    check = config.checks[0]
    runtime = RuntimeContext(actor_tokens={"tenant_a_user": "token"})

    with respx.mock:
        route = respx.post("http://localhost:8000/api/items").mock(
            return_value=httpx.Response(201, text="{}")
        )
        client = TenantGuardHttpClient(
            base_url=config.target.base_url,
            timeout=5.0,
            verify_ssl=True,
            default_headers={},
        )
        client.execute(
            check,
            runtime,
            config,
            rendered_path="/api/items",
            secrets=["token"],
        )
        assert route.calls.last.request.headers["X-Test"] == "1"
        import json

        assert json.loads(route.calls.last.request.content) == {"name": "demo"}


def test_network_error_does_not_leak_token() -> None:
    config = _config()
    check = config.checks[0]
    runtime = RuntimeContext(actor_tokens={"tenant_a_user": "secret-token-value"})

    with respx.mock:
        respx.get("http://localhost:8000/api/items").mock(side_effect=httpx.ConnectError("down"))
        client = TenantGuardHttpClient(
            base_url=config.target.base_url,
            timeout=5.0,
            verify_ssl=True,
            default_headers={},
        )
        with pytest.raises(ClientError) as exc_info:
            client.execute(
                check,
                runtime,
                config,
                rendered_path="/api/items",
                secrets=["secret-token-value"],
            )
    assert "secret-token-value" not in str(exc_info.value)
