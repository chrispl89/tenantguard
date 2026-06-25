"""Authorization check runner."""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import UTC, datetime

from tenantguard.checks.assertions import evaluate_expectations, has_assertion_failures
from tenantguard.checks.severity import Severity
from tenantguard.client import ClientError, TenantGuardHttpClient
from tenantguard.config import (
    CheckConfig,
    ConfigValidationError,
    TenantGuardConfig,
    collect_secrets,
    normalize_filter_tags,
)
from tenantguard.models import RuntimeContext
from tenantguard.results import (
    CheckResult,
    CheckStatus,
    RequestSnapshot,
    RunResult,
    RunSummary,
)
from tenantguard.safety import SafetyError, check_target_scope, check_write_methods, redact_secrets
from tenantguard.templating import render_path


@dataclass(slots=True)
class RunOptions:
    include: list[str] | None = None
    exclude: list[str] | None = None
    tags: list[str] | None = None
    exclude_tags: list[str] | None = None
    verbose: bool = False
    confirm_authorized_scope: bool = False


def _matches_filter(value: str, patterns: list[str]) -> bool:
    lowered = value.lower()
    return any(
        pattern == value or pattern.lower() in lowered for pattern in patterns
    )


def _matches_any_tag(check: CheckConfig, tags: list[str]) -> bool:
    return any(tag in check.tags for tag in tags)


def filter_checks(
    checks: list[CheckConfig],
    *,
    include: list[str] | None,
    exclude: list[str] | None,
    tags: list[str] | None = None,
    exclude_tags: list[str] | None = None,
) -> list[CheckConfig]:
    """Filter checks by id/name substring and optional tags."""
    filtered = checks
    if include:
        filtered = [
            check
            for check in filtered
            if _matches_filter(check.id, include) or _matches_filter(check.name, include)
        ]
    if exclude:
        filtered = [
            check
            for check in filtered
            if not (
                _matches_filter(check.id, exclude) or _matches_filter(check.name, exclude)
            )
        ]
    if tags:
        normalized_tags = normalize_filter_tags(tags)
        filtered = [check for check in filtered if _matches_any_tag(check, normalized_tags)]
    if exclude_tags:
        normalized_exclude_tags = normalize_filter_tags(exclude_tags)
        filtered = [
            check
            for check in filtered
            if not _matches_any_tag(check, normalized_exclude_tags)
        ]
    return filtered


def _build_summary(checks: list[CheckResult]) -> RunSummary:
    passed = sum(1 for check in checks if check.status == CheckStatus.PASSED)
    failed = sum(1 for check in checks if check.status == CheckStatus.FAILED)
    errors = sum(1 for check in checks if check.status == CheckStatus.ERROR)
    skipped = sum(1 for check in checks if check.status == CheckStatus.SKIPPED)
    highest: Severity | None = None
    for check in checks:
        if check.status in {CheckStatus.FAILED, CheckStatus.ERROR}:
            if highest is None or Severity.order(check.severity) > Severity.order(highest):
                highest = check.severity
    return RunSummary(
        total=len(checks),
        passed=passed,
        failed=failed,
        errors=errors,
        skipped=skipped,
        highest_failed_severity=highest,
    )


def _empty_request_snapshot(check: CheckConfig, *, rendered_path: str) -> RequestSnapshot:
    from tenantguard.client import sanitize_headers

    return RequestSnapshot(
        method=check.request.method,
        url="",
        path=rendered_path,
        actor=check.actor,
        headers=sanitize_headers(dict(check.request.headers)),
        json_body=check.request.body_json,
    )


def run_checks(
    config: TenantGuardConfig,
    runtime: RuntimeContext,
    options: RunOptions,
) -> RunResult:
    """Execute configured authorization checks and return aggregated results."""
    check_target_scope(config, confirm_authorized_scope=options.confirm_authorized_scope)
    check_write_methods(config)

    started_at = datetime.now(UTC)
    run_started = time.perf_counter()
    secrets = collect_secrets(config, runtime)

    client = TenantGuardHttpClient(
        base_url=config.target.base_url,
        timeout=float(config.http.timeout_seconds),
        verify_ssl=config.http.verify_tls,
        default_headers={
            **config.http.default_headers,
            "User-Agent": config.http.user_agent,
        },
    )

    selected_checks = filter_checks(
        config.checks,
        include=options.include,
        exclude=options.exclude,
        tags=options.tags,
        exclude_tags=options.exclude_tags,
    )

    if not selected_checks:
        finished_at = datetime.now(UTC)
        return RunResult(
            project_name=config.project.name,
            target_base_url=config.target.base_url,
            started_at=started_at,
            finished_at=finished_at,
            elapsed_ms=(time.perf_counter() - run_started) * 1000,
            checks=[],
            summary=RunSummary(
                total=0,
                passed=0,
                failed=0,
                errors=0,
                skipped=0,
                highest_failed_severity=None,
            ),
        )

    if len(selected_checks) > config.safety.max_requests_per_run:
        msg = (
            f"Selected {len(selected_checks)} checks exceeds "
            f"safety.max_requests_per_run ({config.safety.max_requests_per_run})."
        )
        raise SafetyError(msg)

    check_results: list[CheckResult] = []
    delay_seconds = config.safety.request_delay_ms / 1000

    for index, check in enumerate(selected_checks):
        if index > 0 and delay_seconds > 0:
            time.sleep(delay_seconds)

        check_started = datetime.now(UTC)
        perf_started = time.perf_counter()

        try:
            rendered_path = render_path(check.request.path, config, check_id=check.id)
        except ConfigValidationError as exc:
            elapsed_ms = (time.perf_counter() - perf_started) * 1000
            check_results.append(
                CheckResult(
                    id=check.id,
                    name=check.name,
                    severity=check.severity,
                    actor=check.actor,
                    status=CheckStatus.ERROR,
                    request=_empty_request_snapshot(check, rendered_path=check.request.path),
                    response=None,
                    assertions=[],
                    error_message=redact_secrets(str(exc), secrets),
                    started_at=check_started,
                    finished_at=datetime.now(UTC),
                    elapsed_ms=elapsed_ms,
                )
            )
            continue

        try:
            request_snapshot, response_snapshot, http_response = client.execute(
                check,
                runtime,
                config,
                rendered_path=rendered_path,
                secrets=secrets,
            )
        except ClientError as exc:
            elapsed_ms = (time.perf_counter() - perf_started) * 1000
            check_results.append(
                CheckResult(
                    id=check.id,
                    name=check.name,
                    severity=check.severity,
                    actor=check.actor,
                    status=CheckStatus.ERROR,
                    request=_empty_request_snapshot(check, rendered_path=rendered_path),
                    response=None,
                    assertions=[],
                    error_message=str(exc),
                    started_at=check_started,
                    finished_at=datetime.now(UTC),
                    elapsed_ms=elapsed_ms,
                )
            )
            continue

        assertion_results = evaluate_expectations(
            check,
            http_response,
            elapsed_ms=response_snapshot.elapsed_ms or 0.0,
            secrets=secrets,
        )
        failed = has_assertion_failures(assertion_results)
        status = CheckStatus.FAILED if failed else CheckStatus.PASSED
        elapsed_ms = (time.perf_counter() - perf_started) * 1000

        check_results.append(
            CheckResult(
                id=check.id,
                name=check.name,
                severity=check.severity,
                actor=check.actor,
                status=status,
                request=request_snapshot,
                response=response_snapshot,
                assertions=assertion_results,
                error_message=None,
                started_at=check_started,
                finished_at=datetime.now(UTC),
                elapsed_ms=elapsed_ms,
            )
        )

    finished_at = datetime.now(UTC)
    elapsed_ms = (time.perf_counter() - run_started) * 1000
    summary = _build_summary(check_results)
    return RunResult(
        project_name=config.project.name,
        target_base_url=config.target.base_url,
        started_at=started_at,
        finished_at=finished_at,
        elapsed_ms=elapsed_ms,
        checks=check_results,
        summary=summary,
    )
