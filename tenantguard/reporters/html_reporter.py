"""HTML report generator."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from tenantguard.results import (
    AssertionResult,
    AssertionStatus,
    CheckResult,
    CheckStatus,
    RunResult,
)

RESPONSIBLE_USE_FOOTER = (
    "TenantGuard is intended only for applications you own, maintain, "
    "or are explicitly authorized to test."
)


def _esc(value: Any) -> str:
    """Escape dynamic content for safe HTML output."""
    if value is None:
        return ""
    return html.escape(str(value))


def _format_headers(headers: dict[str, str]) -> str:
    if not headers:
        return "none"
    return "\n".join(f"{key}: {value}" for key, value in headers.items())


def _format_json_body(body: Any) -> str:
    if body is None:
        return "none"
    return json.dumps(body, indent=2, sort_keys=True)


def _render_assertions(assertions: list[AssertionResult]) -> str:
    if not assertions:
        return "<p>none</p>"
    rows: list[str] = []
    for assertion in assertions:
        rows.append(
            "<tr>"
            f"<td>{_esc(assertion.name)}</td>"
            f"<td>{_esc(assertion.status.value)}</td>"
            f"<td>{_esc(assertion.message)}</td>"
            f"<td><pre>{_esc(assertion.expected)}</pre></td>"
            f"<td><pre>{_esc(assertion.actual)}</pre></td>"
            "</tr>"
        )
    return (
        "<table class='assertions'>"
        "<thead><tr>"
        "<th>Name</th><th>Status</th><th>Message</th><th>Expected</th><th>Actual</th>"
        "</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def _render_evidence(check: CheckResult) -> str:
    response = check.response
    response_status = response.status_code if response else "n/a"
    response_headers = _format_headers(response.headers) if response else "none"
    response_body = response.body_snippet if response and response.body_snippet else "none"
    request_body = _format_json_body(check.request.json_body)

    return (
        "<details class='evidence'>"
        "<summary>Request and response evidence</summary>"
        "<div class='evidence-grid'>"
        "<div><h4>Request headers</h4>"
        f"<pre>{_esc(_format_headers(check.request.headers))}</pre></div>"
        "<div><h4>Request body</h4>"
        f"<pre>{_esc(request_body)}</pre></div>"
        "<div><h4>Response status</h4>"
        f"<pre>{_esc(response_status)}</pre></div>"
        "<div><h4>Response headers</h4>"
        f"<pre>{_esc(response_headers)}</pre></div>"
        "<div><h4>Response body snippet</h4>"
        f"<pre>{_esc(response_body)}</pre></div>"
        "<div><h4>Assertion results</h4>"
        f"{_render_assertions(check.assertions)}</div>"
        "</div></details>"
    )


def _render_check_card(check: CheckResult, *, variant: str) -> str:
    status_code = check.response.status_code if check.response else "n/a"
    failed_assertions = [
        assertion
        for assertion in check.assertions
        if assertion.status in {AssertionStatus.FAILED, AssertionStatus.ERROR}
    ]
    failed_lines = (
        "".join(
            f"<li><strong>{_esc(assertion.name)}</strong>: {_esc(assertion.message)}</li>"
            for assertion in failed_assertions
        )
        or "<li>none</li>"
    )
    error_block = ""
    if check.error_message:
        error_block = (
            "<p><strong>Error:</strong> "
            f"<span class='error-message'>{_esc(check.error_message)}</span></p>"
        )

    return (
        f"<article class='check-card {variant}'>"
        f"<header><h3>{_esc(check.id)} — {_esc(check.name)}</h3>"
        f"<span class='badge severity-{_esc(check.severity.value)}'>"
        f"{_esc(check.severity.value)}</span></header>"
        "<dl class='meta'>"
        f"<div><dt>Status</dt><dd>{_esc(check.status.value)}</dd></div>"
        f"<div><dt>Actor</dt><dd>{_esc(check.actor)}</dd></div>"
        f"<div><dt>Duration</dt><dd>{_esc(f'{check.elapsed_ms:.2f} ms')}</dd></div>"
        f"<div><dt>Request</dt><dd>"
        f"{_esc(check.request.method)} {_esc(check.request.path)}</dd></div>"
        f"<div><dt>Response status</dt><dd>{_esc(status_code)}</dd></div>"
        "</dl>"
        f"{error_block}"
        f"<div class='failed-assertions'><h4>Failed assertions</h4><ul>{failed_lines}</ul></div>"
        f"{_render_evidence(check)}"
        "</article>"
    )


def _render_passed_row(check: CheckResult) -> str:
    return (
        "<tr>"
        f"<td>{_esc(check.id)}</td>"
        f"<td>{_esc(check.name)}</td>"
        f"<td>{_esc(check.severity.value)}</td>"
        f"<td>{_esc(check.actor)}</td>"
        f"<td>{_esc(check.status.value)}</td>"
        f"<td>{_esc(f'{check.elapsed_ms:.2f} ms')}</td>"
        "</tr>"
    )


def _summary_card(label: str, value: Any) -> str:
    return (
        f'<div class="summary-card"><span class="muted">{_esc(label)}</span>'
        f"<strong>{_esc(value)}</strong></div>"
    )


def render_html_report(result: RunResult) -> str:
    """Render a RunResult as a self-contained HTML document."""
    summary = result.summary
    highest = summary.highest_failed_severity.value if summary.highest_failed_severity else "none"

    failed_checks = [check for check in result.checks if check.status == CheckStatus.FAILED]
    error_checks = [check for check in result.checks if check.status == CheckStatus.ERROR]
    passed_checks = [check for check in result.checks if check.status == CheckStatus.PASSED]

    failed_html = (
        "".join(_render_check_card(check, variant="failed") for check in failed_checks)
        or "<p class='empty'>No failed checks.</p>"
    )
    error_html = (
        "".join(_render_check_card(check, variant="error") for check in error_checks)
        or "<p class='empty'>No errored checks.</p>"
    )
    passed_rows = "".join(_render_passed_row(check) for check in passed_checks) or (
        "<tr><td colspan='6'>No passed checks.</td></tr>"
    )

    summary_cards = "".join(
        [
            _summary_card("Total", summary.total),
            _summary_card("Passed", summary.passed),
            _summary_card("Failed", summary.failed),
            _summary_card("Errors", summary.errors),
            _summary_card("Skipped", summary.skipped),
            _summary_card("Highest failed severity", highest),
        ]
    )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{_esc(result.project_name)} — TenantGuard Report</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f7f8fa;
      --card: #ffffff;
      --text: #1f2937;
      --muted: #6b7280;
      --border: #d1d5db;
      --critical: #991b1b;
      --high: #b45309;
      --medium: #92400e;
      --low: #1d4ed8;
      --passed: #166534;
      --failed: #b91c1c;
      --error: #7c2d12;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
    }}
    main {{
      max-width: 1100px;
      margin: 0 auto;
      padding: 24px;
    }}
    header.page-header, section, footer {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
      margin-bottom: 20px;
    }}
    h1, h2, h3, h4 {{ margin-top: 0; }}
    .muted {{ color: var(--muted); }}
    .summary-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 12px;
      margin-top: 16px;
    }}
    .summary-card {{
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 12px;
      background: #fafafa;
    }}
    .summary-card strong {{
      display: block;
      font-size: 1.4rem;
    }}
    .check-card {{
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 16px;
      margin-bottom: 16px;
      background: #fff;
    }}
    .check-card.failed {{ border-left: 4px solid var(--failed); }}
    .check-card.error {{ border-left: 4px solid var(--error); }}
    .badge {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 0.85rem;
      text-transform: uppercase;
    }}
    .severity-critical {{ background: #fee2e2; color: var(--critical); }}
    .severity-high {{ background: #ffedd5; color: var(--high); }}
    .severity-medium {{ background: #fef3c7; color: var(--medium); }}
    .severity-low {{ background: #dbeafe; color: var(--low); }}
    .meta {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 8px 16px;
      margin: 12px 0;
    }}
    .meta div {{ margin: 0; }}
    .meta dt {{ font-weight: 600; color: var(--muted); font-size: 0.85rem; }}
    .meta dd {{ margin: 0; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.95rem;
    }}
    th, td {{
      border: 1px solid var(--border);
      padding: 8px 10px;
      text-align: left;
      vertical-align: top;
    }}
    th {{ background: #f3f4f6; }}
    pre {{
      white-space: pre-wrap;
      word-break: break-word;
      background: #f9fafb;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 10px;
      margin: 0;
      font-size: 0.9rem;
    }}
    details.evidence {{
      margin-top: 12px;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 10px;
      background: #fcfcfd;
    }}
    .evidence-grid {{
      display: grid;
      gap: 12px;
      margin-top: 12px;
    }}
    .empty {{ color: var(--muted); }}
    footer {{ font-size: 0.95rem; color: var(--muted); }}
  </style>
</head>
<body>
  <main>
    <header class="page-header">
      <h1>TenantGuard Report</h1>
      <p class="muted">Project: <strong>{_esc(result.project_name)}</strong></p>
      <p class="muted">Target: <strong>{_esc(result.target_base_url)}</strong></p>
      <p class="muted">Started: {_esc(result.started_at.isoformat())}</p>
      <p class="muted">Finished: {_esc(result.finished_at.isoformat())}</p>
      <p class="muted">Elapsed: {_esc(f'{result.elapsed_ms:.2f} ms')}</p>
    </header>

    <section>
      <h2>Summary</h2>
      <div class="summary-grid">
        {summary_cards}
      </div>
    </section>

    <section>
      <h2>Failed checks</h2>
      {failed_html}
    </section>

    <section>
      <h2>Error checks</h2>
      {error_html}
    </section>

    <section>
      <h2>Passed checks</h2>
      <table>
        <thead>
          <tr>
            <th>Check ID</th>
            <th>Name</th>
            <th>Severity</th>
            <th>Actor</th>
            <th>Status</th>
            <th>Duration</th>
          </tr>
        </thead>
        <tbody>
          {passed_rows}
        </tbody>
      </table>
    </section>

    <footer>
      <p>{_esc(RESPONSIBLE_USE_FOOTER)}</p>
    </footer>
  </main>
</body>
</html>
"""


def write_html_report(result: RunResult, output_path: Path) -> Path:
    """Write an HTML report to disk."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_html_report(result), encoding="utf-8")
    return output_path
