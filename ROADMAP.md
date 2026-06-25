# Roadmap

TenantGuard is a config-driven authorization regression testing tool. Items below are planned future work unless marked as shipped.

## Shipped in v0.1.2

- YAML config validation and explicit HTTP check runner
- Safety gates (authorized scope, write methods, request limits)
- Bearer and cookie actor authentication
- JSON, Markdown, and self-contained HTML reports
- FastAPI demo app (read-only and write-method checks)
- Optional check tags, `--tag` / `--exclude-tag` filters, and `--list-checks`

## Planned

- CSRF support for session-cookie applications
- OpenAPI config helper (generate starter checks from an API spec)
- GitHub Action wrapper for CI workflows
- PyPI / pipx packaging (`pip install tenantguard`)
- pytest plugin for in-process authorization checks
- Richer docs and recipe examples
- Richer assertion library (additional matchers and helpers)

## Out of scope

- General-purpose vulnerability scanning
- Endpoint discovery or crawling
- Brute force or credential attacks
- Rate-limit bypassing
- Browser automation or login flows
- Unauthorized testing of third-party systems
