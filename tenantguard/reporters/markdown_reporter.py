"""Markdown report generator."""

from __future__ import annotations

from pathlib import Path

from tenantguard.results import AssertionStatus, CheckResult, CheckStatus, RunResult


def _format_failed_assertions(check: CheckResult) -> str:
    lines: list[str] = []
    for assertion in check.assertions:
        if assertion.status in {AssertionStatus.FAILED, AssertionStatus.ERROR}:
            lines.append(f"- {assertion.name}: {assertion.message}")
    return "\n".join(lines) if lines else "- None"


def render_markdown_report(result: RunResult) -> str:
    """Render a RunResult as Markdown."""
    summary = result.summary
    lines = [
        "# TenantGuard Report",
        "",
        "## Summary",
        "",
        f"- Project: {result.project_name}",
        f"- Target: {result.target_base_url}",
        f"- Started: {result.started_at.isoformat()}",
        f"- Finished: {result.finished_at.isoformat()}",
        f"- Duration: {result.elapsed_ms:.2f} ms",
        f"- Total: {summary.total}",
        f"- Passed: {summary.passed}",
        f"- Failed: {summary.failed}",
        f"- Errors: {summary.errors}",
        f"- Highest failed severity: {summary.highest_failed_severity or 'none'}",
        "",
        "## Findings",
        "",
    ]

    findings = [
        check
        for check in result.checks
        if check.status in {CheckStatus.FAILED, CheckStatus.ERROR}
    ]
    if not findings:
        lines.append("No failed or errored checks.")
        lines.append("")
    else:
        for check in findings:
            status_code = check.response.status_code if check.response else "n/a"
            duration = f"{check.elapsed_ms:.2f} ms"
            request_line = f"{check.request.method} {check.request.path}"
            lines.extend(
                [
                    f"### [{check.severity.value.upper()}] {check.id} — {check.name}",
                    "",
                    f"- Status: {check.status.value}",
                    f"- Actor: {check.actor}",
                    f"- Request: {request_line}",
                    f"- Actual status code: {status_code}",
                    f"- Duration: {duration}",
                    f"- Error: {check.error_message or 'none'}",
                    "- Failed assertions:",
                    _format_failed_assertions(check),
                    "",
                ]
            )
            if (
                check.response
                and check.response.body_snippet
                and check.status == CheckStatus.FAILED
            ):
                lines.extend(
                    [
                        "Response snippet:",
                        "",
                        "```",
                        check.response.body_snippet,
                        "```",
                        "",
                    ]
                )

    lines.extend(
        [
            "## Passed checks",
            "",
            "| Check ID | Name | Severity | Status | Duration |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for check in result.checks:
        if check.status == CheckStatus.PASSED:
            lines.append(
                f"| {check.id} | {check.name} | {check.severity.value} | "
                f"{check.status.value} | {check.elapsed_ms:.2f} ms |"
            )

    lines.append("")
    return "\n".join(lines)


def write_markdown_report(result: RunResult, output_path: Path) -> Path:
    """Write a Markdown report to disk."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_markdown_report(result), encoding="utf-8")
    return output_path
