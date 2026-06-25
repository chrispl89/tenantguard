"""Tests for CLI commands."""

from __future__ import annotations

from pathlib import Path

import yaml
from typer.testing import CliRunner

from tenantguard.cli import app

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.stdout


def test_sample_config() -> None:
    result = runner.invoke(app, ["sample-config"])
    assert result.exit_code == 0
    assert "token_env" in result.stdout


def test_init_does_not_overwrite_without_force(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    existing = tmp_path / "tenantguard.yml"
    existing.write_text("existing: true\n", encoding="utf-8")

    result = runner.invoke(app, ["init"])
    assert result.exit_code == 0
    assert "Skipped existing file" in result.stdout
    assert existing.read_text(encoding="utf-8") == "existing: true\n"
    assert not (tmp_path / "reports" / ".gitkeep").exists()


def test_init_force_overwrites(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    existing = tmp_path / "tenantguard.yml"
    existing.write_text("existing: true\n", encoding="utf-8")

    result = runner.invoke(app, ["init", "--force"])
    assert result.exit_code == 0
    assert "Created tenantguard.yml" in result.stdout
    assert "version:" in existing.read_text(encoding="utf-8")
    assert (tmp_path / "reports").is_dir()


def test_validate_example_config() -> None:
    config_path = Path("examples/configs/tenantguard.basic.yml")
    result = runner.invoke(app, ["validate", str(config_path)])
    assert result.exit_code == 0
    assert "Configuration is valid." in result.stdout


def test_validate_with_env_requires_token_vars(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    config = {
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
                "name": "Example",
                "severity": "high",
                "actor": "tenant_a_user",
                "request": {"method": "GET", "path": "/api/items"},
                "expect": {"status_in": [403]},
            }
        ],
    }
    config_path = tmp_path / "tenantguard.yml"
    config_path.write_text(yaml.dump(config), encoding="utf-8")
    env_path = tmp_path / ".env.local"
    env_path.write_text("TENANT_A_USER_TOKEN=secret\n", encoding="utf-8")

    result = runner.invoke(
        app,
        ["validate", str(config_path), "--env", str(env_path)],
    )
    assert result.exit_code == 0
    assert "secret" not in result.stdout


def test_inline_token_warning(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    config = {
        "version": "0.1",
        "target": {"base_url": "http://localhost:8000"},
        "actors": {
            "tenant_a_user": {
                "tenant_id": "tenant_a",
                "role": "user",
                "auth": {"type": "bearer", "token": "inline-secret"},
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
    config_path = tmp_path / "tenantguard.yml"
    config_path.write_text(yaml.dump(config), encoding="utf-8")

    result = runner.invoke(app, ["validate", str(config_path)])
    assert result.exit_code == 0
    assert "Prefer token_env" in result.stdout
    assert "inline-secret" not in result.stdout


def test_run_dry_run_shows_planned_checks(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    config = {
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
                "name": "Example",
                "severity": "high",
                "actor": "tenant_a_user",
                "request": {"method": "GET", "path": "/api/items"},
                "expect": {"status_in": [403]},
            }
        ],
    }
    config_path = tmp_path / "tenantguard.yml"
    config_path.write_text(yaml.dump(config), encoding="utf-8")
    env_path = tmp_path / ".env.local"
    env_path.write_text("TENANT_A_USER_TOKEN=secret\n", encoding="utf-8")

    result = runner.invoke(
        app,
        ["run", str(config_path), "--env", str(env_path), "--dry-run"],
    )
    assert result.exit_code == 0
    assert "Planned checks" in result.stdout
    assert "TG-001" in result.stdout
    assert "secret" not in result.stdout


def test_include_exclude_filter_dry_run_and_runner(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    config = {
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
                "name": "One",
                "severity": "high",
                "actor": "tenant_a_user",
                "request": {"method": "GET", "path": "/one"},
                "expect": {"status_in": [403]},
            },
            {
                "id": "TG-002",
                "name": "Two",
                "severity": "high",
                "actor": "tenant_a_user",
                "request": {"method": "GET", "path": "/two"},
                "expect": {"status_in": [403]},
            },
        ],
    }
    config_path = tmp_path / "tenantguard.yml"
    config_path.write_text(yaml.dump(config), encoding="utf-8")
    env_path = tmp_path / ".env.local"
    env_path.write_text("TENANT_A_USER_TOKEN=secret\n", encoding="utf-8")

    dry_result = runner.invoke(
        app,
        [
            "run",
            str(config_path),
            "--env",
            str(env_path),
            "--dry-run",
            "--include",
            "TG-001",
        ],
    )
    assert dry_result.exit_code == 0
    assert "TG-001" in dry_result.stdout
    assert "TG-002" not in dry_result.stdout

    import httpx
    import respx

    with respx.mock:
        respx.get("http://localhost:8000/one").mock(
            return_value=httpx.Response(403, text="forbidden")
        )
        run_result = runner.invoke(
            app,
            [
                "run",
                str(config_path),
                "--env",
                str(env_path),
                "--include",
                "TG-001",
            ],
        )
    assert run_result.exit_code == 0
    assert "Total: 1" in run_result.stdout
    assert "Passed: 1" in run_result.stdout
    assert "secret" not in run_result.stdout


def test_run_executes_runner_and_writes_json_report(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    config = {
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
                "name": "Example",
                "severity": "low",
                "actor": "tenant_a_user",
                "request": {"method": "GET", "path": "/api/items"},
                "expect": {"status_in": [403, 404]},
            }
        ],
    }
    config_path = tmp_path / "tenantguard.yml"
    config_path.write_text(yaml.dump(config), encoding="utf-8")
    env_path = tmp_path / ".env.local"
    env_path.write_text("TENANT_A_USER_TOKEN=secret\n", encoding="utf-8")
    report_path = tmp_path / "reports" / "report.json"

    import httpx
    import respx

    with respx.mock:
        respx.get("http://localhost:8000/api/items").mock(
            return_value=httpx.Response(200, text="ok")
        )
        result = runner.invoke(
            app,
            [
                "run",
                str(config_path),
                "--env",
                str(env_path),
                "--report",
                "json",
                "--output",
                str(report_path),
            ],
        )

    assert result.exit_code == 1
    assert report_path.exists()
    assert "Report written to:" in result.stdout
    assert "secret" not in report_path.read_text(encoding="utf-8")


def _report_run_config(tmp_path: Path) -> tuple[Path, Path]:
    config = {
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
                "name": "Example",
                "severity": "low",
                "actor": "tenant_a_user",
                "request": {"method": "GET", "path": "/api/items"},
                "expect": {"status_in": [403, 404]},
            }
        ],
    }
    config_path = tmp_path / "tenantguard.yml"
    config_path.write_text(yaml.dump(config), encoding="utf-8")
    env_path = tmp_path / ".env.local"
    env_path.write_text("TENANT_A_USER_TOKEN=secret\n", encoding="utf-8")
    return config_path, env_path


def test_run_executes_runner_and_writes_html_report(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    config_path, env_path = _report_run_config(tmp_path)
    report_path = tmp_path / "reports" / "report.html"

    import httpx
    import respx

    with respx.mock:
        respx.get("http://localhost:8000/api/items").mock(
            return_value=httpx.Response(200, text="ok")
        )
        result = runner.invoke(
            app,
            [
                "run",
                str(config_path),
                "--env",
                str(env_path),
                "--report",
                "html",
                "--output",
                str(report_path),
            ],
        )

    assert result.exit_code == 1
    assert report_path.exists()
    report_text = report_path.read_text(encoding="utf-8")
    assert "<!doctype html>" in report_text.lower()
    assert "Report written to:" in result.stdout
    assert "secret" not in report_text


def test_run_executes_runner_and_writes_markdown_report(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    config_path, env_path = _report_run_config(tmp_path)
    report_path = tmp_path / "reports" / "report.md"

    import httpx
    import respx

    with respx.mock:
        respx.get("http://localhost:8000/api/items").mock(
            return_value=httpx.Response(200, text="ok")
        )
        result = runner.invoke(
            app,
            [
                "run",
                str(config_path),
                "--env",
                str(env_path),
                "--report",
                "markdown",
                "--output",
                str(report_path),
            ],
        )

    assert result.exit_code == 1
    assert report_path.exists()
    assert "# TenantGuard Report" in report_path.read_text(encoding="utf-8")
    assert "Report written to:" in result.stdout


def test_run_rejects_invalid_report_format(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    config_path, env_path = _report_run_config(tmp_path)
    result = runner.invoke(
        app,
        [
            "run",
            str(config_path),
            "--env",
            str(env_path),
            "--report",
            "pdf",
        ],
    )
    assert result.exit_code != 0


def test_run_fail_on_high_ignores_low_severity_failure(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    config = {
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
                "name": "Example",
                "severity": "low",
                "actor": "tenant_a_user",
                "request": {"method": "GET", "path": "/api/items"},
                "expect": {"status_in": [403, 404]},
            }
        ],
    }
    config_path = tmp_path / "tenantguard.yml"
    config_path.write_text(yaml.dump(config), encoding="utf-8")
    env_path = tmp_path / ".env.local"
    env_path.write_text("TENANT_A_USER_TOKEN=secret\n", encoding="utf-8")

    import httpx
    import respx

    with respx.mock:
        respx.get("http://localhost:8000/api/items").mock(
            return_value=httpx.Response(200, text="ok")
        )
        result = runner.invoke(
            app,
            [
                "run",
                str(config_path),
                "--env",
                str(env_path),
                "--fail-on",
                "high",
            ],
        )
    assert result.exit_code == 0


def test_run_public_target_without_confirmation_exits_3(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    config = {
        "version": "0.1",
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
    config_path = tmp_path / "tenantguard.yml"
    config_path.write_text(yaml.dump(config), encoding="utf-8")
    env_path = tmp_path / ".env.local"
    env_path.write_text("TENANT_A_USER_TOKEN=secret\n", encoding="utf-8")

    result = runner.invoke(
        app,
        ["run", str(config_path), "--env", str(env_path)],
    )
    assert result.exit_code == 3
    assert "Public target detected" in result.stdout
