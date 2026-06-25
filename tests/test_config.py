"""Tests for configuration loading and validation."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from tenantguard.config import (
    AuthConfig,
    ConfigValidationError,
    load_config,
    resolve_tokens,
    validate_config_structure,
    validate_token_env,
    warn_inline_tokens,
)
from tenantguard.safety import SafetyError, check_write_methods
from tenantguard.templating import render_path


def _write_config(tmp_path: Path, data: dict) -> Path:
    path = tmp_path / "tenantguard.yml"
    path.write_text(yaml.dump(data), encoding="utf-8")
    return path


def _base_config() -> dict:
    return {
        "version": "0.1",
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
                "name": "Example check",
                "severity": "high",
                "actor": "tenant_a_user",
                "request": {"method": "GET", "path": "/api/items/1"},
                "expect": {"status_in": [403, 404]},
            }
        ],
    }


def test_load_valid_config(tmp_path: Path) -> None:
    path = _write_config(tmp_path, _base_config())
    config = load_config(path)
    assert config.target.base_url == "http://localhost:8000"


@pytest.mark.parametrize(
    "base_url",
    [
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://[::1]:8000",
        "http://10.0.0.5:8080",
        "http://192.168.1.1/api",
    ],
)
def test_base_url_accepts_local_and_private_hosts(tmp_path: Path, base_url: str) -> None:
    data = _base_config()
    data["target"]["base_url"] = base_url
    config = load_config(_write_config(tmp_path, data))
    assert config.target.base_url == base_url


def test_check_missing_actor_field_fails_validation(tmp_path: Path) -> None:
    data = _base_config()
    del data["checks"][0]["actor"]
    with pytest.raises(ConfigValidationError):
        load_config(_write_config(tmp_path, data))


def test_check_unknown_actor_fails_structure_validation(tmp_path: Path) -> None:
    data = _base_config()
    data["checks"][0]["actor"] = "missing_actor"
    config = load_config(_write_config(tmp_path, data))
    with pytest.raises(ConfigValidationError, match="unknown actor"):
        validate_config_structure(config)


def test_duplicate_check_id_fails_structure_validation(tmp_path: Path) -> None:
    data = _base_config()
    data["checks"].append(dict(data["checks"][0]))
    config = load_config(_write_config(tmp_path, data))
    with pytest.raises(ConfigValidationError, match="Duplicate check id: TG-001"):
        validate_config_structure(config)


def test_request_method_is_normalized_to_uppercase(tmp_path: Path) -> None:
    data = _base_config()
    data["checks"][0]["request"]["method"] = "get"
    config = load_config(_write_config(tmp_path, data))
    assert config.checks[0].request.method == "GET"


def test_unknown_request_method_fails_validation(tmp_path: Path) -> None:
    data = _base_config()
    data["checks"][0]["request"]["method"] = "TRACE"
    with pytest.raises(ConfigValidationError, match="Unsupported HTTP method"):
        load_config(_write_config(tmp_path, data))


def test_missing_token_env_when_required(tmp_path: Path) -> None:
    config = load_config(_write_config(tmp_path, _base_config()))
    with pytest.raises(ConfigValidationError, match="Missing environment variables"):
        validate_token_env(config, {}, required=True)


def test_resolve_tokens_returns_runtime_context_without_mutating_config(tmp_path: Path) -> None:
    data = _base_config()
    data["actors"]["tenant_a_user"]["auth"] = {
        "type": "bearer",
        "token_env": "TENANT_A_USER_TOKEN",
    }
    config = load_config(_write_config(tmp_path, data))
    runtime = resolve_tokens(config, {"TENANT_A_USER_TOKEN": "secret-token-value"})
    assert runtime.actor_tokens["tenant_a_user"] == "secret-token-value"
    assert config.actors["tenant_a_user"].auth.token is None
    assert "secret-token-value" not in repr(config)
    assert "secret-token-value" not in repr(runtime)


def test_write_methods_blocked_when_disabled(tmp_path: Path) -> None:
    data = _base_config()
    data["checks"][0]["request"]["method"] = "POST"
    config = load_config(_write_config(tmp_path, data))
    with pytest.raises(SafetyError, match="Write method checks are disabled"):
        check_write_methods(config)


def test_token_not_leaked_in_missing_env_error(tmp_path: Path) -> None:
    data = _base_config()
    data["actors"]["tenant_a_user"]["auth"] = {
        "type": "bearer",
        "token_env": "TENANT_A_USER_TOKEN",
    }
    config = load_config(_write_config(tmp_path, data))
    with pytest.raises(ConfigValidationError) as exc_info:
        resolve_tokens(config, {})
    assert "TENANT_A_USER_TOKEN" in str(exc_info.value)
    assert "super-secret-value" not in str(exc_info.value)


def test_render_resource_placeholder(tmp_path: Path) -> None:
    data = _base_config()
    data["resources"] = {
        "tenant_b_invoice": {
            "type": "invoice",
            "id": "inv_b_001",
            "tenant_id": "tenant_b",
        }
    }
    data["checks"][0]["request"]["path"] = "/api/invoices/{{ resources.tenant_b_invoice.id }}"
    config = load_config(_write_config(tmp_path, data))
    assert render_path(config.checks[0].request.path, config) == "/api/invoices/inv_b_001"


def test_render_actor_placeholder(tmp_path: Path) -> None:
    data = _base_config()
    data["checks"][0]["request"]["path"] = "/api/tenants/{{ actors.tenant_a_user.tenant_id }}"
    config = load_config(_write_config(tmp_path, data))
    assert render_path(config.checks[0].request.path, config) == "/api/tenants/tenant_a"


def test_unknown_resource_placeholder_raises(tmp_path: Path) -> None:
    data = _base_config()
    data["checks"][0]["request"]["path"] = "/api/invoices/{{ resources.missing.id }}"
    config = load_config(_write_config(tmp_path, data))
    with pytest.raises(ConfigValidationError, match="Unknown resource placeholder"):
        render_path(config.checks[0].request.path, config)


def test_bearer_auth_config_loads_successfully(tmp_path: Path) -> None:
    config = load_config(_write_config(tmp_path, _base_config()))
    assert config.actors["tenant_a_user"].auth.type == "bearer"
    assert config.actors["tenant_a_user"].auth.cookie_name is None


def test_cookie_auth_config_loads_successfully(tmp_path: Path) -> None:
    data = _base_config()
    data["actors"] = {
        "client_a": {
            "label": "Client A",
            "tenant_id": "client_a",
            "role": "client",
            "auth": {
                "type": "cookie",
                "cookie_name": "bb_session",
                "token_env": "CLIENT_A_SESSION",
            },
        }
    }
    data["checks"][0]["actor"] = "client_a"
    config = load_config(_write_config(tmp_path, data))
    auth = config.actors["client_a"].auth
    assert auth.type == "cookie"
    assert auth.cookie_name == "bb_session"
    assert auth.token_env == "CLIENT_A_SESSION"


def test_cookie_auth_without_cookie_name_fails_validation(tmp_path: Path) -> None:
    data = _base_config()
    data["actors"]["tenant_a_user"]["auth"] = {
        "type": "cookie",
        "token_env": "CLIENT_A_SESSION",
    }
    with pytest.raises(ConfigValidationError, match="cookie_name is required"):
        load_config(_write_config(tmp_path, data))


def test_cookie_auth_with_empty_cookie_name_fails_validation(tmp_path: Path) -> None:
    data = _base_config()
    data["actors"]["tenant_a_user"]["auth"] = {
        "type": "cookie",
        "cookie_name": "",
        "token_env": "CLIENT_A_SESSION",
    }
    with pytest.raises(ConfigValidationError, match="cookie_name is required"):
        load_config(_write_config(tmp_path, data))


@pytest.mark.parametrize("cookie_name", ["bb session", "bb/session", "bb;session", ""])
def test_cookie_auth_with_invalid_cookie_name_fails_validation(
    tmp_path: Path, cookie_name: str
) -> None:
    if not cookie_name:
        pytest.skip("empty cookie_name covered by required-field test")
    data = _base_config()
    data["actors"]["tenant_a_user"]["auth"] = {
        "type": "cookie",
        "cookie_name": cookie_name,
        "token_env": "CLIENT_A_SESSION",
    }
    with pytest.raises(ConfigValidationError, match="Invalid cookie_name"):
        load_config(_write_config(tmp_path, data))


def test_bearer_auth_with_cookie_name_fails_validation(tmp_path: Path) -> None:
    data = _base_config()
    data["actors"]["tenant_a_user"]["auth"] = {
        "type": "bearer",
        "token_env": "TENANT_A_USER_TOKEN",
        "cookie_name": "bb_session",
    }
    with pytest.raises(ConfigValidationError, match="cookie_name is only allowed"):
        load_config(_write_config(tmp_path, data))


def test_resolve_tokens_works_for_cookie_auth(tmp_path: Path) -> None:
    data = _base_config()
    data["actors"]["tenant_a_user"]["auth"] = {
        "type": "cookie",
        "cookie_name": "bb_session",
        "token_env": "CLIENT_A_SESSION",
    }
    config = load_config(_write_config(tmp_path, data))
    runtime = resolve_tokens(config, {"CLIENT_A_SESSION": "secret-cookie-value"})
    assert runtime.actor_tokens["tenant_a_user"] == "secret-cookie-value"


def test_warn_inline_tokens_includes_cookie_auth_actor(tmp_path: Path) -> None:
    data = _base_config()
    data["actors"]["tenant_a_user"]["auth"] = {
        "type": "cookie",
        "cookie_name": "bb_session",
        "token": "inline-cookie-secret",
    }
    config = load_config(_write_config(tmp_path, data))
    assert warn_inline_tokens(config) == ["tenant_a_user"]


def test_cookie_auth_secret_not_leaked_in_repr(tmp_path: Path) -> None:
    data = _base_config()
    data["actors"]["tenant_a_user"]["auth"] = {
        "type": "cookie",
        "cookie_name": "bb_session",
        "token": "secret-cookie-value",
    }
    config = load_config(_write_config(tmp_path, data))
    assert "secret-cookie-value" not in repr(config)
    assert "secret-cookie-value" not in repr(config.actors["tenant_a_user"].auth)
    assert repr(AuthConfig.model_validate(data["actors"]["tenant_a_user"]["auth"])) == (
        "AuthConfig(type='cookie', cookie_name='bb_session', token=<redacted>)"
    )


def test_unknown_actor_placeholder_raises(tmp_path: Path) -> None:
    data = _base_config()
    data["checks"][0]["request"]["path"] = "/api/tenants/{{ actors.missing.tenant_id }}"
    config = load_config(_write_config(tmp_path, data))
    with pytest.raises(ConfigValidationError, match="Unknown actor placeholder"):
        render_path(config.checks[0].request.path, config)
