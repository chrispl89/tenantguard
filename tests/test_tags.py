"""Tests for check tags, tag filters, and config ergonomics."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx
import yaml
from typer.testing import CliRunner

from tenantguard.cli import NO_CHECKS_MATCHED_MESSAGE, app
from tenantguard.config import (
    ConfigValidationError,
    TenantGuardConfig,
    find_unused_actors,
    find_unused_resources,
    load_config,
    normalize_tag,
    validate_config_structure,
)
from tenantguard.runner import RunOptions, filter_checks, run_checks
from tenantguard.templating import render_path

runner = CliRunner()


def _write_config(tmp_path: Path, data: dict) -> Path:
    path = tmp_path / "tenantguard.yml"
    path.write_text(yaml.dump(data), encoding="utf-8")
    return path


def _base_config(*, tags: list[str] | None = None) -> dict:
    check: dict = {
        "id": "TG-001",
        "name": "First check",
        "severity": "high",
        "actor": "tenant_a_user",
        "request": {"method": "GET", "path": "/one"},
        "expect": {"status_in": [200]},
    }
    if tags is not None:
        check["tags"] = tags
    return {
        "target": {"base_url": "http://localhost:8000"},
        "actors": {
            "tenant_a_user": {
                "tenant_id": "tenant_a",
                "role": "user",
                "auth": {"type": "bearer", "token_env": "TENANT_A_USER_TOKEN"},
            },
            "tenant_b_user": {
                "tenant_id": "tenant_b",
                "role": "user",
                "auth": {"type": "bearer", "token_env": "TENANT_B_USER_TOKEN"},
            },
        },
        "resources": {
            "invoice_a": {"type": "invoice", "id": "inv_a_001", "tenant_id": "tenant_a"},
            "invoice_b": {"type": "invoice", "id": "inv_b_001", "tenant_id": "tenant_b"},
        },
        "checks": [
            check,
            {
                "id": "TG-002",
                "name": "Second check",
                "severity": "high",
                "actor": "tenant_a_user",
                "tags": ["write", "tenant-isolation"],
                "request": {"method": "GET", "path": "/two"},
                "expect": {"status_in": [200]},
            },
            {
                "id": "TG-003",
                "name": "Third check",
                "severity": "high",
                "actor": "tenant_a_user",
                "tags": ["read-only", "admin-access"],
                "request": {"method": "GET", "path": "/three"},
                "expect": {"status_in": [200]},
            },
        ],
    }


def test_tags_are_optional(tmp_path: Path) -> None:
    config = load_config(_write_config(tmp_path, _base_config()))
    assert config.checks[0].tags == []


def test_tags_normalize_to_lowercase(tmp_path: Path) -> None:
    config = load_config(_write_config(tmp_path, _base_config(tags=["Tenant-Isolation"])))
    assert config.checks[0].tags == ["tenant-isolation"]


def test_tags_trim_whitespace(tmp_path: Path) -> None:
    config = load_config(_write_config(tmp_path, _base_config(tags=["  read-only  "])))
    assert config.checks[0].tags == ["read-only"]


def test_duplicate_tags_are_deduplicated(tmp_path: Path) -> None:
    config = load_config(
        _write_config(tmp_path, _base_config(tags=["read-only", "Read-Only", "write"]))
    )
    assert config.checks[0].tags == ["read-only", "write"]


@pytest.mark.parametrize(
    "invalid_tag",
    ["tenant isolation", "tenant/isolation", "admin:access", "@critical"],
)
def test_invalid_tags_fail_validation(tmp_path: Path, invalid_tag: str) -> None:
    with pytest.raises(ConfigValidationError, match="Invalid tag"):
        load_config(_write_config(tmp_path, _base_config(tags=[invalid_tag])))


def test_filter_by_tag() -> None:
    config = TenantGuardConfig.model_validate(_base_config(tags=["horizontal-access"]))
    filtered = filter_checks(config.checks, include=None, exclude=None, tags=["tenant-isolation"])
    assert [check.id for check in filtered] == ["TG-002"]


def test_repeatable_tag_filter_uses_or_semantics() -> None:
    config = TenantGuardConfig.model_validate(_base_config(tags=["horizontal-access"]))
    filtered = filter_checks(
        config.checks,
        include=None,
        exclude=None,
        tags=["tenant-isolation", "admin-access"],
    )
    assert {check.id for check in filtered} == {"TG-002", "TG-003"}


def test_exclude_tag_filter() -> None:
    config = TenantGuardConfig.model_validate(_base_config())
    filtered = filter_checks(
        config.checks,
        include=None,
        exclude=None,
        exclude_tags=["write"],
    )
    assert {check.id for check in filtered} == {"TG-001", "TG-003"}


def test_tag_and_exclude_tag_together() -> None:
    config = TenantGuardConfig.model_validate(_base_config())
    filtered = filter_checks(
        config.checks,
        include=None,
        exclude=None,
        tags=["tenant-isolation", "admin-access"],
        exclude_tags=["write"],
    )
    assert [check.id for check in filtered] == ["TG-003"]


def test_include_exclude_still_work_with_tags() -> None:
    config = TenantGuardConfig.model_validate(_base_config())
    filtered = filter_checks(
        config.checks,
        include=["TG-002"],
        exclude=None,
        tags=["tenant-isolation"],
    )
    assert [check.id for check in filtered] == ["TG-002"]


def test_filter_order_include_then_exclude_then_tag() -> None:
    config = TenantGuardConfig.model_validate(_base_config())
    filtered = filter_checks(
        config.checks,
        include=["check"],
        exclude=["Third"],
        tags=["read-only"],
    )
    assert filtered == []


def test_unknown_actor_error_lists_available_actors(tmp_path: Path) -> None:
    data = _base_config()
    data["checks"][0]["actor"] = "client_c"
    config = load_config(_write_config(tmp_path, data))
    with pytest.raises(ConfigValidationError, match='references unknown actor "client_c"') as exc:
        validate_config_structure(config)
    assert "Available actors:" in str(exc.value)
    assert "tenant_a_user" in str(exc.value)


def test_unknown_resource_placeholder_lists_available_resources(tmp_path: Path) -> None:
    data = _base_config()
    data["checks"][0]["request"]["path"] = "/api/invoices/{{ resources.invoice_c.id }}"
    config = load_config(_write_config(tmp_path, data))
    with pytest.raises(
        ConfigValidationError,
        match='references unknown resource "invoice_c"',
    ) as exc:
        render_path(config.checks[0].request.path, config, check_id=config.checks[0].id)
    assert "Available resources:" in str(exc.value)


def test_unknown_actor_placeholder_lists_available_actors(tmp_path: Path) -> None:
    data = _base_config()
    data["checks"][0]["request"]["path"] = "/api/tenants/{{ actors.client_c.tenant_id }}"
    config = load_config(_write_config(tmp_path, data))
    with pytest.raises(
        ConfigValidationError,
        match='references unknown actor "client_c" in template',
    ) as exc:
        render_path(config.checks[0].request.path, config, check_id=config.checks[0].id)
    assert "Available actors:" in str(exc.value)


def test_find_unused_actors_and_resources() -> None:
    config = TenantGuardConfig.model_validate(_base_config())
    assert find_unused_actors(config) == ["tenant_b_user"]
    assert set(find_unused_resources(config)) == {"invoice_a", "invoice_b"}


def test_list_checks_without_env(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    config_path = _write_config(tmp_path, _base_config(tags=["horizontal-access"]))
    result = runner.invoke(app, ["run", str(config_path), "--list-checks"])
    assert result.exit_code == 0
    assert "TG-001" in result.stdout
    assert "Tags" in result.stdout
    assert "tenant-isolation" in result.stdout or "-" in result.stdout
    assert "secret" not in result.stdout


def test_list_checks_respects_tag_filter(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    config_path = _write_config(tmp_path, _base_config())
    result = runner.invoke(app, ["run", str(config_path), "--list-checks", "--tag", "write"])
    assert result.exit_code == 0
    assert "TG-002" in result.stdout
    assert "TG-003" not in result.stdout


def test_list_checks_no_matches_message(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    config_path = _write_config(tmp_path, _base_config())
    result = runner.invoke(app, ["run", str(config_path), "--list-checks", "--tag", "missing-tag"])
    assert result.exit_code == 0
    assert NO_CHECKS_MATCHED_MESSAGE in result.stdout


def test_dry_run_shows_tags(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    config_path = _write_config(tmp_path, _base_config(tags=["horizontal-access"]))
    env_path = tmp_path / ".env.local"
    env_path.write_text(
        "TENANT_A_USER_TOKEN=secret\nTENANT_B_USER_TOKEN=secret2\n",
        encoding="utf-8",
    )
    result = runner.invoke(
        app,
        ["run", str(config_path), "--env", str(env_path), "--dry-run", "--tag", "write"],
    )
    assert result.exit_code == 0
    assert "write" in result.stdout
    assert "secret" not in result.stdout


def test_run_with_no_matching_checks_exits_zero(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    config_path = _write_config(tmp_path, _base_config())
    env_path = tmp_path / ".env.local"
    env_path.write_text(
        "TENANT_A_USER_TOKEN=secret\nTENANT_B_USER_TOKEN=secret2\n",
        encoding="utf-8",
    )
    result = runner.invoke(
        app,
        ["run", str(config_path), "--env", str(env_path), "--tag", "missing-tag"],
    )
    assert result.exit_code == 0
    assert NO_CHECKS_MATCHED_MESSAGE in result.stdout


def test_validate_shows_unused_warnings(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    config_path = _write_config(tmp_path, _base_config())
    result = runner.invoke(app, ["validate", str(config_path)])
    assert result.exit_code == 0
    assert 'Warning: actor "tenant_b_user"' in result.stdout
    assert 'Warning: resource "invoice_a"' in result.stdout


def test_runner_tag_filter_executes_matching_checks() -> None:
    from tenantguard.config import resolve_tokens

    config = TenantGuardConfig.model_validate(_base_config())
    runtime = resolve_tokens(
        config,
        {"TENANT_A_USER_TOKEN": "secret", "TENANT_B_USER_TOKEN": "secret2"},
    )
    with respx.mock:
        respx.get("http://localhost:8000/two").mock(
            return_value=httpx.Response(200, text="ok")
        )
        result = run_checks(
            config,
            runtime,
            RunOptions(tags=["write"]),
        )
    assert result.summary.total == 1
    assert result.checks[0].id == "TG-002"


def test_normalize_tag_cli_input() -> None:
    assert normalize_tag(" Tenant-Isolation ") == "tenant-isolation"
