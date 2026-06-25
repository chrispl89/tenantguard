# Changelog

## 0.1.2 - Unreleased

- Added self-contained HTML reports for TenantGuard run results.
- Added request/response evidence and assertion details to HTML reports.
- Added tests to ensure HTML reports escape dynamic content and do not leak secrets.
- Added an example HTML report under `examples/reports/`.

## 0.1.1 - Unreleased

- Added cookie-based actor authentication with redacted Cookie headers.
- Added tests for cookie auth config validation and secret redaction.
- Documented cookie-based authentication in README.

## 0.1.0 - Unreleased

Initial local MVP:

- YAML configuration validation and structure checks
- Safety pre-checks for authorized scope and write methods
- HTTP runner for explicitly configured checks
- Core authorization assertions
- JSON and Markdown reports
- Vulnerable FastAPI demo application with end-to-end examples
