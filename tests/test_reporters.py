"""Tests for report generators."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from tenantguard.checks.severity import Severity
from tenantguard.client import sanitize_headers
from tenantguard.reporters.json_reporter import render_json_report
from tenantguard.reporters.markdown_reporter import render_markdown_report
from tenantguard.results import (
    AssertionResult,
    AssertionStatus,
    CheckResult,
    CheckStatus,
    RequestSnapshot,
    ResponseSnapshot,
    RunResult,
    RunSummary,
)


def _sample_result() -> RunResult:
    started = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    finished = datetime(2026, 1, 1, 12, 0, 1, tzinfo=UTC)
    request = RequestSnapshot(
        method="GET",
        url="http://localhost:8000/api/items",
        path="/api/items",
        actor="tenant_a_user",
        headers=sanitize_headers(
            {"Authorization": "Bearer secret-token-value", "Accept": "application/json"}
        ),
        json_body=None,
    )
    response = ResponseSnapshot(
        status_code=200,
        headers={"content-type": "application/json"},
        body_snippet='{"tenant":"tenant_b"}',
        elapsed_ms=12.5,
    )
    failed_check = CheckResult(
        id="TG-001",
        name="Tenant leak",
        severity=Severity.CRITICAL,
        actor="tenant_a_user",
        status=CheckStatus.FAILED,
        request=request,
        response=response,
        assertions=[
            AssertionResult(
                name="status_in",
                status=AssertionStatus.FAILED,
                message="Expected status in [403, 404], got 200.",
                expected=[403, 404],
                actual=200,
            )
        ],
        error_message=None,
        started_at=started,
        finished_at=finished,
        elapsed_ms=12.5,
    )
    passed_check = CheckResult(
        id="TG-002",
        name="Secure endpoint",
        severity=Severity.HIGH,
        actor="tenant_a_user",
        status=CheckStatus.PASSED,
        request=request,
        response=response,
        assertions=[],
        error_message=None,
        started_at=started,
        finished_at=finished,
        elapsed_ms=10.0,
    )
    return RunResult(
        project_name="Demo",
        target_base_url="http://localhost:8000",
        started_at=started,
        finished_at=finished,
        elapsed_ms=1000.0,
        checks=[failed_check, passed_check],
        summary=RunSummary(
            total=2,
            passed=1,
            failed=1,
            errors=0,
            skipped=0,
            highest_failed_severity=Severity.CRITICAL,
        ),
    )


def test_json_reporter_produces_valid_json_without_tokens() -> None:
    payload = json.loads(render_json_report(_sample_result()))
    rendered = json.dumps(payload)
    assert payload["project_name"] == "Demo"
    assert payload["summary"]["failed"] == 1
    assert "secret-token-value" not in rendered
    assert "[REDACTED]" in rendered


def test_reporters_redact_cookie_session_values() -> None:
    request = RequestSnapshot(
        method="GET",
        url="http://localhost:8000/api/me",
        path="/api/me",
        actor="client_a",
        headers={"Cookie": "bb_session=[REDACTED]", "Accept": "application/json"},
        json_body=None,
    )
    started = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    finished = datetime(2026, 1, 1, 12, 0, 1, tzinfo=UTC)
    check = CheckResult(
        id="COOKIE-001",
        name="Client profile",
        severity=Severity.MEDIUM,
        actor="client_a",
        status=CheckStatus.PASSED,
        request=request,
        response=ResponseSnapshot(
            status_code=200,
            headers={"content-type": "application/json"},
            body_snippet='{"id":"client_a"}',
            elapsed_ms=10.0,
        ),
        assertions=[],
        error_message=None,
        started_at=started,
        finished_at=finished,
        elapsed_ms=10.0,
    )
    result = RunResult(
        project_name="Cookie demo",
        target_base_url="http://localhost:8000",
        started_at=started,
        finished_at=finished,
        elapsed_ms=100.0,
        checks=[check],
        summary=RunSummary(
            total=1,
            passed=1,
            failed=0,
            errors=0,
            skipped=0,
            highest_failed_severity=None,
        ),
    )

    json_output = render_json_report(result)
    markdown_output = render_markdown_report(result)
    assert "[REDACTED]" in json_output
    assert "secret-cookie-value" not in json_output
    assert "secret-cookie-value" not in markdown_output


def test_markdown_reporter_contains_summary_and_findings_without_tokens() -> None:
    markdown = render_markdown_report(_sample_result())
    assert "# TenantGuard Report" in markdown
    assert "## Summary" in markdown
    assert "## Findings" in markdown
    assert "TG-001" in markdown
    assert "## Passed checks" in markdown
    assert "| Check ID | Name | Severity | Status | Duration |" in markdown
    assert "| --- | --- | --- | --- | --- |" in markdown
    assert "secret-token-value" not in markdown
    assert "Bearer secret" not in markdown
