"""Tests for the authorization check runner."""

from __future__ import annotations

import httpx
import pytest
import respx

from tenantguard.config import TenantGuardConfig, resolve_tokens
from tenantguard.models import RuntimeContext
from tenantguard.results import CheckStatus
from tenantguard.runner import RunOptions, run_checks
from tenantguard.safety import SafetyError


def _make_config(data: dict) -> tuple[TenantGuardConfig, RuntimeContext]:
    config = TenantGuardConfig.model_validate(data)
    runtime = resolve_tokens(
        config,
        {"TENANT_A_USER_TOKEN": "secret-token", "TENANT_B_USER_TOKEN": "secret-token-2"},
    )
    return config, runtime


def test_runner_returns_passed_check() -> None:
    config, runtime = _make_config(
        {
            "target": {"base_url": "http://localhost:8000"},
            "actors": {
                "tenant_a_user": {
                    "tenant_id": "tenant_a",
                    "role": "user",
                    "auth": {"type": "bearer", "token_env": "TENANT_A_USER_TOKEN"},
                }
            },
            "checks": [
                {
                    "id": "TG-001",
                    "name": "Example",
                    "severity": "high",
                    "actor": "tenant_a_user",
                    "request": {"method": "GET", "path": "/api/items"},
                    "expect": {"status_in": [200]},
                }
            ],
        }
    )

    with respx.mock:
        respx.get("http://localhost:8000/api/items").mock(
            return_value=httpx.Response(200, text="ok")
        )
        result = run_checks(config, runtime, RunOptions())

    assert result.summary.passed == 1
    assert result.checks[0].status == CheckStatus.PASSED


def test_runner_cookie_auth_passes_without_leaking_session() -> None:
    config = TenantGuardConfig.model_validate(
        {
            "target": {"base_url": "http://localhost:8000"},
            "actors": {
                "client_a": {
                    "tenant_id": "client_a",
                    "role": "client",
                    "auth": {
                        "type": "cookie",
                        "cookie_name": "bb_session",
                        "token_env": "CLIENT_A_SESSION",
                    },
                }
            },
            "checks": [
                {
                    "id": "COOKIE-001",
                    "name": "Client profile",
                    "severity": "medium",
                    "actor": "client_a",
                    "request": {"method": "GET", "path": "/api/me"},
                    "expect": {"status_in": [200]},
                }
            ],
        }
    )
    runtime = resolve_tokens(config, {"CLIENT_A_SESSION": "secret-cookie-value"})

    with respx.mock:
        respx.get("http://localhost:8000/api/me").mock(
            return_value=httpx.Response(200, text="{}")
        )
        result = run_checks(config, runtime, RunOptions())

    assert result.summary.passed == 1
    assert result.checks[0].status == CheckStatus.PASSED
    serialized = str(result)
    assert "secret-cookie-value" not in serialized
    assert result.checks[0].request.headers["Cookie"] == "bb_session=[REDACTED]"


def test_runner_returns_failed_on_assertion_mismatch() -> None:
    config, runtime = _make_config(
        {
            "target": {"base_url": "http://localhost:8000"},
            "actors": {
                "tenant_a_user": {
                    "tenant_id": "tenant_a",
                    "role": "user",
                    "auth": {"type": "bearer", "token_env": "TENANT_A_USER_TOKEN"},
                }
            },
            "checks": [
                {
                    "id": "TG-001",
                    "name": "Example",
                    "severity": "high",
                    "actor": "tenant_a_user",
                    "request": {"method": "GET", "path": "/api/items"},
                    "expect": {"status_in": [403, 404]},
                }
            ],
        }
    )

    with respx.mock:
        respx.get("http://localhost:8000/api/items").mock(
            return_value=httpx.Response(200, text="ok")
        )
        result = run_checks(config, runtime, RunOptions())

    assert result.summary.failed == 1
    assert result.checks[0].status == CheckStatus.FAILED


def test_runner_marks_network_error_as_error_and_continues() -> None:
    config, runtime = _make_config(
        {
            "target": {"base_url": "http://localhost:8000"},
            "actors": {
                "tenant_a_user": {
                    "tenant_id": "tenant_a",
                    "role": "user",
                    "auth": {"type": "bearer", "token_env": "TENANT_A_USER_TOKEN"},
                }
            },
            "checks": [
                {
                    "id": "TG-001",
                    "name": "First",
                    "severity": "high",
                    "actor": "tenant_a_user",
                    "request": {"method": "GET", "path": "/one"},
                    "expect": {"status_in": [200]},
                },
                {
                    "id": "TG-002",
                    "name": "Second",
                    "severity": "high",
                    "actor": "tenant_a_user",
                    "request": {"method": "GET", "path": "/two"},
                    "expect": {"status_in": [200]},
                },
            ],
        }
    )

    with respx.mock:
        respx.get("http://localhost:8000/one").mock(side_effect=httpx.ConnectError("down"))
        respx.get("http://localhost:8000/two").mock(
            return_value=httpx.Response(200, text="ok")
        )
        result = run_checks(config, runtime, RunOptions())

    assert result.summary.errors == 1
    assert result.summary.passed == 1
    assert result.checks[0].status == CheckStatus.ERROR
    assert result.checks[1].status == CheckStatus.PASSED
    assert "secret-token" not in (result.checks[0].error_message or "")


def test_include_exclude_filter_checks() -> None:
    config, runtime = _make_config(
        {
            "target": {"base_url": "http://localhost:8000"},
            "actors": {
                "tenant_a_user": {
                    "tenant_id": "tenant_a",
                    "role": "user",
                    "auth": {"type": "bearer", "token_env": "TENANT_A_USER_TOKEN"},
                }
            },
            "checks": [
                {
                    "id": "TG-001",
                    "name": "First check",
                    "severity": "high",
                    "actor": "tenant_a_user",
                    "request": {"method": "GET", "path": "/one"},
                    "expect": {"status_in": [200]},
                },
                {
                    "id": "TG-002",
                    "name": "Second check",
                    "severity": "high",
                    "actor": "tenant_a_user",
                    "request": {"method": "GET", "path": "/two"},
                    "expect": {"status_in": [200]},
                },
            ],
        }
    )

    with respx.mock:
        respx.get("http://localhost:8000/two").mock(
            return_value=httpx.Response(200, text="ok")
        )
        result = run_checks(
            config,
            runtime,
            RunOptions(include=["Second"]),
        )

    assert result.summary.total == 1
    assert result.checks[0].id == "TG-002"


def test_public_target_blocked_without_confirmation() -> None:
    config, runtime = _make_config(
        {
            "target": {"base_url": "https://example.com"},
            "actors": {
                "tenant_a_user": {
                    "tenant_id": "tenant_a",
                    "role": "user",
                    "auth": {"type": "bearer", "token_env": "TENANT_A_USER_TOKEN"},
                }
            },
            "checks": [
                {
                    "id": "TG-001",
                    "name": "Example",
                    "severity": "high",
                    "actor": "tenant_a_user",
                    "request": {"method": "GET", "path": "/api/items"},
                    "expect": {"status_in": [200]},
                }
            ],
        }
    )

    with pytest.raises(SafetyError):
        run_checks(config, runtime, RunOptions(confirm_authorized_scope=False))


def test_write_methods_blocked_before_requests() -> None:
    config, runtime = _make_config(
        {
            "target": {"base_url": "http://localhost:8000"},
            "safety": {"allow_write_methods": False},
            "actors": {
                "tenant_a_user": {
                    "tenant_id": "tenant_a",
                    "role": "user",
                    "auth": {"type": "bearer", "token_env": "TENANT_A_USER_TOKEN"},
                }
            },
            "checks": [
                {
                    "id": "TG-001",
                    "name": "Write",
                    "severity": "high",
                    "actor": "tenant_a_user",
                    "request": {"method": "POST", "path": "/api/items"},
                    "expect": {"status_in": [201]},
                }
            ],
        }
    )

    with pytest.raises(SafetyError):
        run_checks(config, runtime, RunOptions())


def test_template_path_substituted_before_request() -> None:
    config, runtime = _make_config(
        {
            "target": {"base_url": "http://localhost:8000"},
            "actors": {
                "tenant_a_user": {
                    "tenant_id": "tenant_a",
                    "role": "user",
                    "auth": {"type": "bearer", "token_env": "TENANT_A_USER_TOKEN"},
                }
            },
            "resources": {
                "invoice_b": {"type": "invoice", "id": "inv_b_001", "tenant_id": "tenant_b"}
            },
            "checks": [
                {
                    "id": "TG-001",
                    "name": "Example",
                    "severity": "high",
                    "actor": "tenant_a_user",
                    "request": {
                        "method": "GET",
                        "path": "/api/invoices/{{ resources.invoice_b.id }}",
                    },
                    "expect": {"status_in": [200]},
                }
            ],
        }
    )

    with respx.mock:
        route = respx.get("http://localhost:8000/api/invoices/inv_b_001").mock(
            return_value=httpx.Response(200, text="ok")
        )
        run_checks(config, runtime, RunOptions())
        assert route.called


def test_config_and_runtime_not_mutated() -> None:
    config, runtime = _make_config(
        {
            "target": {"base_url": "http://localhost:8000"},
            "actors": {
                "tenant_a_user": {
                    "tenant_id": "tenant_a",
                    "role": "user",
                    "auth": {"type": "bearer", "token_env": "TENANT_A_USER_TOKEN"},
                }
            },
            "checks": [
                {
                    "id": "TG-001",
                    "name": "Example",
                    "severity": "high",
                    "actor": "tenant_a_user",
                    "request": {"method": "GET", "path": "/api/items"},
                    "expect": {"status_in": [200]},
                }
            ],
        }
    )
    original_path = config.checks[0].request.path
    original_tokens = dict(runtime.actor_tokens)

    with respx.mock:
        respx.get("http://localhost:8000/api/items").mock(
            return_value=httpx.Response(200, text="ok")
        )
        run_checks(config, runtime, RunOptions())

    assert config.checks[0].request.path == original_path
    assert runtime.actor_tokens == original_tokens
