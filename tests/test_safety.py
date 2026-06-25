"""Tests for safety guards."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from tenantguard.config import TenantGuardConfig, load_config
from tenantguard.safety import (
    PUBLIC_TARGET_MESSAGE,
    SafetyError,
    check_target_scope,
    is_local_or_private_host,
    is_public_target,
)


def _config_with_target(base_url: str) -> TenantGuardConfig:
    data = {
        "version": "0.1",
        "target": {"base_url": base_url},
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
                "request": {"method": "GET", "path": "/api/items"},
                "expect": {"status_in": [403]},
            }
        ],
    }
    path = Path("tmp-config.yml")
    path.write_text(yaml.dump(data), encoding="utf-8")
    try:
        return load_config(path)
    finally:
        path.unlink(missing_ok=True)


@pytest.mark.parametrize(
    "base_url",
    [
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://[::1]:8000",
        "http://10.0.0.5:8080",
        "http://192.168.1.1",
    ],
)
def test_local_and_private_hosts(base_url: str) -> None:
    assert is_local_or_private_host(base_url) is True
    assert is_public_target(base_url) is False


@pytest.mark.parametrize(
    "base_url",
    [
        "http://api.internal.corp:8000",
        "https://example.com",
    ],
)
def test_public_hosts(base_url: str) -> None:
    assert is_local_or_private_host(base_url) is False
    assert is_public_target(base_url) is True


def test_public_target_requires_confirmation() -> None:
    config = _config_with_target("https://example.com")
    with pytest.raises(SafetyError, match=PUBLIC_TARGET_MESSAGE):
        check_target_scope(config, confirm_authorized_scope=False)


def test_public_target_allowed_with_confirmation() -> None:
    config = _config_with_target("https://example.com")
    check_target_scope(config, confirm_authorized_scope=True)
