# Changelog

All notable changes to this project are documented here.

## 0.1.2 - 2026-06-12

First public-ready release combining the local MVP and follow-up improvements.

### Core

- YAML configuration validation and structure checks
- Safety pre-checks for authorized scope and write methods
- HTTP runner for explicitly configured checks
- Core authorization assertions (`status_in`, body/header/json matchers)
- JSON and Markdown reports
- Vulnerable FastAPI demo application with end-to-end examples

### Authentication

- Bearer token authentication via `token_env`
- Cookie-based session authentication with redacted Cookie headers in reports

### Reports

- Self-contained HTML reports with request/response evidence and assertion details
- Secret redaction for bearer tokens and cookie session values in all report formats
- Example HTML and Markdown reports under `examples/reports/`

### Write-method demo

- PATCH authorization checks in the demo app and dedicated write-method config
- `allow_write_methods` safety gate for explicit write checks

### Config ergonomics

- Optional check tags for organizing larger authorization test suites
- `--tag` and `--exclude-tag` filters (repeatable, OR semantics)
- `--list-checks` for safe inspection without token resolution or HTTP requests
- Improved validation messages for unknown actors/resources
- Warnings for unused actors and resources
