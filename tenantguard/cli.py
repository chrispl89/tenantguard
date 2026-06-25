"""TenantGuard command-line interface."""

from __future__ import annotations

from collections import Counter
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from tenantguard import __version__
from tenantguard.checks.severity import Severity
from tenantguard.config import (
    DEFAULT_USER_AGENT,
    CheckConfig,
    ConfigValidationError,
    TenantGuardConfig,
    collect_secrets,
    find_unused_actors,
    find_unused_resources,
    load_config,
    load_env_file,
    resolve_tokens,
    validate_config_structure,
    validate_token_env,
    warn_inline_tokens,
)
from tenantguard.models import ExitCode, RuntimeContext
from tenantguard.reporters.html_reporter import write_html_report
from tenantguard.reporters.json_reporter import write_json_report
from tenantguard.reporters.markdown_reporter import write_markdown_report
from tenantguard.results import CheckStatus, RunResult
from tenantguard.runner import RunOptions, filter_checks, run_checks
from tenantguard.safety import SafetyError, check_target_scope, check_write_methods, redact_secrets
from tenantguard.templating import render_path

app = typer.Typer(
    name="tenantguard",
    help="Authorization regression tests for multi-tenant SaaS applications.",
    no_args_is_help=True,
)
console = Console()

INIT_CONFIG = f"""version: "0.1"

project:
  name: "My SaaS Authorization Checks"
  description: "Authorization regression tests for a multi-tenant SaaS API"

target:
  base_url: "http://localhost:8000"
  authorized: true

safety:
  allow_write_methods: false
  confirm_authorized_scope: true
  max_requests_per_run: 100
  request_delay_ms: 100
  redact_sensitive_values: true

http:
  timeout_seconds: 10
  verify_tls: true
  user_agent: "{DEFAULT_USER_AGENT}"
  default_headers:
    Accept: "application/json"
    Content-Type: "application/json"

actors:
  tenant_a_user:
    label: "Tenant A regular user"
    tenant_id: "tenant_a"
    role: "user"
    auth:
      type: "bearer"
      token_env: "TENANT_A_USER_TOKEN"

  tenant_b_user:
    label: "Tenant B regular user"
    tenant_id: "tenant_b"
    role: "user"
    auth:
      type: "bearer"
      token_env: "TENANT_B_USER_TOKEN"

resources:
  tenant_a_invoice:
    type: "invoice"
    id: "inv_a_001"
    tenant_id: "tenant_a"
    owner_actor: "tenant_a_user"

  tenant_b_invoice:
    type: "invoice"
    id: "inv_b_001"
    tenant_id: "tenant_b"
    owner_actor: "tenant_b_user"

checks:
  - id: "TG-001"
    name: "Tenant A user cannot access Tenant B invoice"
    description: "A regular user from tenant A must not read tenant B data."
    severity: "critical"
    actor: "tenant_a_user"
    request:
      method: "GET"
      path: "/api/invoices/{{ resources.tenant_b_invoice.id }}"
    expect:
      status_in: [403, 404]
"""

INIT_ENV = """TENANT_A_USER_TOKEN=replace_me
TENANT_B_USER_TOKEN=replace_me
"""

SAMPLE_CONFIG = INIT_CONFIG
MAX_UNUSED_WARNINGS = 10
NO_CHECKS_MATCHED_MESSAGE = "No checks matched the selected filters."


class ReportFormat(StrEnum):
    NONE = "none"
    JSON = "json"
    MARKDOWN = "markdown"
    HTML = "html"


def _write_file(path: Path, content: str, *, force: bool) -> bool:
    if path.exists() and not force:
        console.print(f"[yellow]Skipped existing file:[/yellow] {path}")
        return False
    path.write_text(content, encoding="utf-8")
    console.print(f"[green]Created[/green] {path}")
    return True


def _print_inline_token_warning(config: TenantGuardConfig) -> None:
    inline_actors = warn_inline_tokens(config)
    if inline_actors:
        console.print(
            "[yellow]Warning: inline bearer tokens in config are supported for local "
            "experiments only. Prefer token_env for safer secret handling.[/yellow]"
        )
        console.print(f"[yellow]Actors with inline tokens:[/yellow] {', '.join(inline_actors)}")


def _load_and_validate(
    config_path: Path,
    *,
    env_path: Path | None,
    require_token_env: bool,
) -> tuple[TenantGuardConfig, dict[str, str]]:
    try:
        config = load_config(config_path)
        validate_config_structure(config)
        env = load_env_file(env_path)
        validate_token_env(config, env, required=require_token_env)
    except ConfigValidationError as exc:
        console.print(f"[red]Configuration error:[/red] {exc}")
        raise typer.Exit(code=ExitCode.INVALID_CONFIG) from exc
    return config, env


def _load_config_structure(config_path: Path) -> TenantGuardConfig:
    try:
        config = load_config(config_path)
        validate_config_structure(config)
    except ConfigValidationError as exc:
        console.print(f"[red]Configuration error:[/red] {exc}")
        raise typer.Exit(code=ExitCode.INVALID_CONFIG) from exc
    return config


def _format_tags(tags: list[str]) -> str:
    return ", ".join(tags) if tags else "-"


def _print_unused_warnings(config: TenantGuardConfig) -> None:
    warnings: list[str] = []
    for actor_id in find_unused_actors(config):
        warnings.append(
            f'Warning: actor "{actor_id}" is defined but not used by any check.'
        )
    for resource_id in find_unused_resources(config):
        warnings.append(
            f'Warning: resource "{resource_id}" is defined but not used by any check.'
        )
    if not warnings:
        return
    for warning in warnings[:MAX_UNUSED_WARNINGS]:
        console.print(f"[yellow]{warning}[/yellow]")
    remaining = len(warnings) - MAX_UNUSED_WARNINGS
    if remaining > 0:
        console.print(f"[yellow]...and {remaining} more.[/yellow]")


def _print_checks_table(
    checks: list[CheckConfig],
    *,
    title: str,
    config: TenantGuardConfig | None = None,
    secrets: list[str] | None = None,
) -> None:
    table = Table(title=title)
    table.add_column("Check ID")
    table.add_column("Severity")
    table.add_column("Actor")
    table.add_column("Tags")
    table.add_column("Method")
    table.add_column("Path")
    table.add_column("Name")
    for check in checks:
        path = check.request.path
        if config is not None:
            try:
                path = render_path(check.request.path, config, check_id=check.id)
            except ConfigValidationError:
                path = check.request.path
            if secrets is not None:
                path = redact_secrets(path, secrets)
        table.add_row(
            check.id,
            check.severity.value,
            check.actor,
            _format_tags(check.tags),
            check.request.method,
            path,
            check.name,
        )
    console.print(table)


def _print_validate_summary(config: TenantGuardConfig) -> None:
    console.print("[green]Configuration is valid.[/green]\n")
    console.print("Target:")
    console.print(f"  {config.target.base_url}\n")
    console.print("Actors:")
    for actor_id in config.actors:
        console.print(f"  {actor_id}")
    console.print()
    severity_counts = Counter(check.severity.value for check in config.checks)
    console.print("Checks:")
    console.print(f"  {len(config.checks)} checks configured")
    for severity, count in sorted(severity_counts.items()):
        console.print(f"  {count} {severity}")


def _print_dry_run_plan(
    config: TenantGuardConfig,
    runtime: RuntimeContext,
    checks: list[CheckConfig],
) -> None:
    secrets = collect_secrets(config, runtime)
    _print_checks_table(
        checks,
        title="Planned checks",
        config=config,
        secrets=secrets,
    )
    console.print(f"\n[bold]{len(checks)}[/bold] check(s) planned against {config.target.base_url}")


def _should_fail(result: RunResult, fail_on: Severity) -> bool:
    threshold = Severity.order(fail_on)
    for check in result.checks:
        if check.status in {CheckStatus.FAILED, CheckStatus.ERROR}:
            if Severity.order(check.severity) >= threshold:
                return True
    return False


def _print_run_summary(result: RunResult) -> None:
    summary = result.summary
    if summary.total == 0:
        return

    console.print("\n[bold]TenantGuard Run Summary[/bold]")
    console.print(f"Target: {result.target_base_url}")
    console.print(f"Total: {summary.total}")
    console.print(f"[green]Passed: {summary.passed}[/green]")
    console.print(f"[red]Failed: {summary.failed}[/red]")
    console.print(f"[red]Errors: {summary.errors}[/red]")
    console.print(f"Elapsed: {result.elapsed_ms:.2f} ms")
    if summary.highest_failed_severity is not None:
        console.print(f"Highest failed severity: {summary.highest_failed_severity.value}")

    issues = sorted(
        (
            check
            for check in result.checks
            if check.status in {CheckStatus.FAILED, CheckStatus.ERROR}
        ),
        key=lambda check: Severity.order(check.severity),
        reverse=True,
    )
    if issues:
        console.print("\n[bold]Failed and errored checks[/bold]")
        for check in issues:
            status_code = check.response.status_code if check.response else "n/a"
            message = check.error_message
            if not message and check.assertions:
                failed_assertions = [
                    assertion.message
                    for assertion in check.assertions
                    if assertion.status.value in {"failed", "error"}
                ]
                message = failed_assertions[0] if failed_assertions else "Assertion failed."
            console.print(
                f"- [{check.severity.value}] {check.id} {check.name}: "
                f"{check.request.method} {check.request.path} -> {status_code} "
                f"({message or 'see report'})"
            )


def _default_report_path(report_format: ReportFormat) -> Path:
    if report_format == ReportFormat.JSON:
        return Path("reports/tenantguard-report.json")
    if report_format == ReportFormat.HTML:
        return Path("reports/tenantguard-report.html")
    return Path("reports/tenantguard-report.md")


def _write_report(
    result: RunResult,
    report_format: ReportFormat,
    output_path: Path | None,
) -> Path | None:
    if report_format == ReportFormat.NONE:
        return None
    destination = output_path or _default_report_path(report_format)
    if report_format == ReportFormat.JSON:
        return write_json_report(result, destination)
    if report_format == ReportFormat.HTML:
        return write_html_report(result, destination)
    return write_markdown_report(result, destination)


@app.command("version")
def version() -> None:
    """Show TenantGuard version."""
    console.print(__version__)


@app.command("sample-config")
def sample_config() -> None:
    """Print a sample tenantguard.yml configuration."""
    console.print(SAMPLE_CONFIG, end="")


@app.command("init")
def init(
    force: Annotated[
        bool,
        typer.Option("--force", help="Overwrite existing files."),
    ] = False,
) -> None:
    """Create tenantguard.yml, .env.example, and a local reports directory."""
    created_config = _write_file(Path("tenantguard.yml"), INIT_CONFIG, force=force)
    created_env = _write_file(Path(".env.example"), INIT_ENV, force=force)
    reports_dir = Path("reports")
    if reports_dir.exists() and not force:
        console.print(f"[yellow]Skipped existing directory:[/yellow] {reports_dir}")
    else:
        reports_dir.mkdir(parents=True, exist_ok=True)
        console.print(f"[green]Created[/green] {reports_dir}/")

    if created_config or created_env:
        console.print(
            "\nNext steps:\n"
            "1. Add your base URL to tenantguard.yml\n"
            "2. Define at least two actors from different tenants\n"
            "3. Add known resources owned by each tenant\n"
            "4. Run: tenantguard validate tenantguard.yml\n"
            "5. Run: tenantguard run tenantguard.yml --env .env.local"
        )


@app.command("validate")
def validate(
    config_path: Annotated[Path, typer.Argument(help="Path to tenantguard.yml")],
    env: Annotated[
        Path | None,
        typer.Option("--env", help="Load environment variables from a .env file."),
    ] = None,
) -> None:
    """Validate a TenantGuard configuration file."""
    config, _ = _load_and_validate(config_path, env_path=env, require_token_env=env is not None)
    _print_inline_token_warning(config)
    _print_unused_warnings(config)
    _print_validate_summary(config)


@app.command("run")
def run(
    config_path: Annotated[Path, typer.Argument(help="Path to tenantguard.yml")],
    env: Annotated[
        Path | None,
        typer.Option("--env", help="Load environment variables from a .env file."),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Show planned checks without sending HTTP requests."),
    ] = False,
    confirm_authorized_scope: Annotated[
        bool,
        typer.Option(
            "--confirm-authorized-scope",
            help="Confirm that you are authorized to test the configured target.",
        ),
    ] = False,
    include: Annotated[
        list[str] | None,
        typer.Option("--include", help="Include checks by id or name substring."),
    ] = None,
    exclude: Annotated[
        list[str] | None,
        typer.Option("--exclude", help="Exclude checks by id or name substring."),
    ] = None,
    tag: Annotated[
        list[str] | None,
        typer.Option("--tag", help="Include checks with this tag (repeatable, OR semantics)."),
    ] = None,
    exclude_tag: Annotated[
        list[str] | None,
        typer.Option(
            "--exclude-tag",
            help="Exclude checks with this tag (repeatable, OR semantics).",
        ),
    ] = None,
    list_checks: Annotated[
        bool,
        typer.Option(
            "--list-checks",
            help="List configured checks without resolving tokens or sending requests.",
        ),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", help="Show detailed metadata."),
    ] = False,
    report: Annotated[
        ReportFormat,
        typer.Option(
            "--report",
            help="Report format: none, json, markdown, or html.",
        ),
    ] = ReportFormat.NONE,
    output: Annotated[
        Path | None,
        typer.Option("--output", help="Write report to this file path."),
    ] = None,
    fail_on: Annotated[
        Severity,
        typer.Option("--fail-on", help="Exit with code 1 at or above this severity."),
    ] = Severity.LOW,
) -> None:
    """Run authorization checks against a configured target."""
    if list_checks:
        config = _load_config_structure(config_path)
        _print_inline_token_warning(config)
        _print_unused_warnings(config)
        checks = filter_checks(
            config.checks,
            include=include,
            exclude=exclude,
            tags=tag,
            exclude_tags=exclude_tag,
        )
        if not checks:
            console.print(f"[yellow]{NO_CHECKS_MATCHED_MESSAGE}[/yellow]")
            return
        _print_checks_table(checks, title="Configured checks")
        return

    config, env_vars = _load_and_validate(
        config_path,
        env_path=env,
        require_token_env=not dry_run,
    )
    _print_inline_token_warning(config)

    try:
        try:
            runtime = resolve_tokens(config, env_vars)
        except ConfigValidationError:
            if not dry_run:
                raise
            runtime = RuntimeContext()
        if dry_run:
            check_target_scope(config, confirm_authorized_scope=confirm_authorized_scope)
            check_write_methods(config)
            _print_unused_warnings(config)
        checks = filter_checks(
            config.checks,
            include=include,
            exclude=exclude,
            tags=tag,
            exclude_tags=exclude_tag,
        )
        if dry_run:
            if verbose:
                console.print(f"Target: {config.target.base_url}")
                console.print(f"Actors: {', '.join(config.actors.keys())}")
            if not checks:
                console.print(f"[yellow]{NO_CHECKS_MATCHED_MESSAGE}[/yellow]")
                return
            _print_dry_run_plan(config, runtime, checks)
            return

        result = run_checks(
            config,
            runtime,
            RunOptions(
                include=include,
                exclude=exclude,
                tags=tag,
                exclude_tags=exclude_tag,
                verbose=verbose,
                confirm_authorized_scope=confirm_authorized_scope,
            ),
        )
    except ConfigValidationError as exc:
        console.print(f"[red]Configuration error:[/red] {exc}")
        raise typer.Exit(code=ExitCode.INVALID_CONFIG) from exc
    except SafetyError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=ExitCode.SAFETY_CONFIRMATION_REQUIRED) from exc

    _print_run_summary(result)
    report_path = _write_report(result, report, output)
    if report_path is not None:
        console.print(f"\n[green]Report written to:[/green] {report_path}")

    if result.summary.total == 0:
        console.print(f"[yellow]{NO_CHECKS_MATCHED_MESSAGE}[/yellow]")
        return

    if result.summary.failed > 0 or result.summary.errors > 0:
        console.print(
            "\n[dim]Some checks did not pass. Review failed checks above or open the report "
            "for details.[/dim]"
        )
        if "tenantguard-demo" in config_path.name:
            console.print(
                "[dim]Demo configs intentionally include failing checks against vulnerable "
                "endpoints. Exit code 1 is expected unless you raise --fail-on.[/dim]"
            )

    if _should_fail(result, fail_on):
        console.print(
            f"\n[yellow]Findings at or above --fail-on={fail_on.value}. "
            f"Exit code {ExitCode.FINDINGS}.[/yellow]"
        )
        raise typer.Exit(code=ExitCode.FINDINGS)
