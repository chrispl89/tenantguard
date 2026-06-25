"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml


@pytest.fixture
def basic_config_dict() -> dict:
    return {
        "version": "0.1",
        "project": {"name": "Test Project"},
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
                "request": {"method": "GET", "path": "/api/items"},
                "expect": {"status_in": [200]},
            }
        ],
    }


@pytest.fixture
def write_config(tmp_path: Path, basic_config_dict: dict):
    def _write(overrides: dict | None = None) -> Path:
        data = basic_config_dict.copy()
        if overrides:
            data.update(overrides)
        path = tmp_path / "tenantguard.yml"
        path.write_text(yaml.dump(data), encoding="utf-8")
        return path

    return _write
