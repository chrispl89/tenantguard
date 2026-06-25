# TenantGuard

TenantGuard is a config-driven authorization regression testing tool for SaaS applications.

It helps catch bugs where:

- users can access resources from another tenant,
- list endpoints leak foreign records,
- regular users can call admin endpoints,
- AI-generated CRUD endpoints forget ownership checks.

## What TenantGuard is

TenantGuard runs explicit authorization checks that you define in YAML. You provide actors, tokens, known resources, HTTP requests, and expected results. TenantGuard executes those checks and reports pass/fail findings.

It is especially useful after generating SaaS APIs with AI coding tools, where happy-path CRUD tests pass but tenant boundaries are still wrong.

## What TenantGuard is not

TenantGuard is **not** a general-purpose vulnerability scanner. It does not:

- crawl applications,
- discover endpoints automatically,
- brute-force credentials,
- bypass rate limits,
- run exploit payloads,
- test third-party systems without your explicit authorization.

You define every check. TenantGuard verifies authorization boundaries you already understand.

## Responsible Use

- Use TenantGuard only on applications you own, maintain, or are explicitly authorized to test.
- Do not use it against third-party systems without written permission.
- Do not use it for brute force, credential attacks, bypassing rate limits, exploitation, or unauthorized scanning.
- TenantGuard is not a general-purpose vulnerability scanner.

Unauthorized testing may be illegal and harmful. You are responsible for using this tool safely, legally, and ethically.

## Why this exists

Multi-tenant SaaS applications often look correct on the happy path:

- authentication works,
- CRUD tests pass,
- the frontend shows the right data for the logged-in user.

But the API may still return another tenant's invoice, leak foreign records from a list endpoint, or allow a regular user to read admin settings.

Example vulnerable pattern:

```python
@app.get("/api/invoices/{invoice_id}")
def get_invoice(invoice_id: str, user: User = Depends(get_current_user)):
    invoice = db.get_invoice(invoice_id)
    return invoice
```

The endpoint checks authentication, not tenant ownership. TenantGuard is designed to catch that class of mistake before production.

## Installation

TenantGuard is not published to PyPI yet.

Install from this repository:

```bash
git clone https://github.com/chrispl89/tenantguard.git
cd tenantguard
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,demo]"
```

For core-only local usage:

```bash
pip install -e .
```

Planned future installation:

```bash
pip install tenantguard
```

## Quickstart

Create a local config:

```bash
tenantguard init
```

Edit `tenantguard.yml` and prefer `token_env` for secrets:

```yaml
version: "0.1"

target:
  base_url: "http://localhost:8000"
  authorized: true

actors:
  tenant_a_user:
    tenant_id: "tenant_a"
    role: "user"
    auth:
      type: "bearer"
      token_env: "TENANT_A_USER_TOKEN"

checks:
  - id: "TG-001"
    name: "Tenant A user cannot access Tenant B invoice"
    severity: "critical"
    actor: "tenant_a_user"
    request:
      method: "GET"
      path: "/api/invoices/inv_b_001"
    expect:
      status_in: [403, 404]
```

Validate and preview:

```bash
tenantguard validate tenantguard.yml
tenantguard run tenantguard.yml --env .env.local --dry-run
```

## Configuration example

A fuller example is available at [`examples/configs/tenantguard.basic.yml`](examples/configs/tenantguard.basic.yml).

TenantGuard configs define:

- `target.base_url` — API under test
- `actors` — users with bearer or cookie authentication via `token_env`
- `resources` — known object IDs for templated paths
- `checks` — HTTP requests and `expect` assertions
- `safety` — write-method blocking, request limits, redaction

### Bearer authentication

```yaml
auth:
  type: "bearer"
  token_env: "TENANT_A_USER_TOKEN"
```

### Cookie-based authentication

TenantGuard supports session-cookie based applications, which is useful for SaaS apps that rely on session cookies rather than bearer tokens.

```yaml
actors:
  client_a:
    label: "Client A"
    tenant_id: "client_a"
    role: "client"
    auth:
      type: "cookie"
      cookie_name: "bb_session"
      token_env: "CLIENT_A_SESSION"
```

This sends:

```http
Cookie: bb_session=<value from CLIENT_A_SESSION>
```

The cookie value should be stored in a local env file and must not be committed.

Example `.env.local`:

```bash
CLIENT_A_SESSION=replace-with-session-cookie-value
```

Do not paste real session cookies into public configs, reports, or issues.

A minimal cookie-auth example config is available at [`examples/configs/tenantguard.cookie-auth.yml`](examples/configs/tenantguard.cookie-auth.yml).

## Running checks

Run checks against your API:

```bash
tenantguard run tenantguard.yml --env .env.local
```

Generate reports:

```bash
tenantguard run tenantguard.yml \
  --env .env.local \
  --report markdown \
  --output reports/report.md

tenantguard run tenantguard.yml \
  --env .env.local \
  --report json \
  --output reports/report.json
```

Control CI exit behavior:

```bash
tenantguard run tenantguard.yml --env .env.local --fail-on high
```

Filter checks:

```bash
tenantguard run tenantguard.yml --env .env.local --include TG-001
tenantguard run tenantguard.yml --env .env.local --exclude admin
```

Public targets require explicit confirmation:

```bash
tenantguard run tenantguard.yml --confirm-authorized-scope
```

Only use that flag when you own the target or have written permission to test it.

## Supported assertions

TenantGuard evaluates these `expect` fields:

- `status_in`
- `status_not_in`
- `body_contains`
- `body_not_contains`
- `json_path_equals`
- `json_path_not_equals`
- `header_exists`
- `header_equals`
- `max_response_time_ms`

Example:

```yaml
expect:
  status_in: [403, 404]
  body_not_contains:
    - "tenant_b"
```

## Demo: catching cross-tenant access

TenantGuard includes a local FastAPI demo app with intentionally vulnerable endpoints and secure variants.

**Docker Compose** (recommended for manual testing):

```bash
cd examples/vulnerable-fastapi-app
docker compose up --build
```

**Without Docker** (alternative):

```bash
cd examples/vulnerable-fastapi-app
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Run TenantGuard against the demo:

```bash
tenantguard run examples/configs/tenantguard-demo.yml \
  --env examples/vulnerable-fastapi-app/.env.demo \
  --report markdown \
  --output reports/demo-report.md
```

Expected outcome:

- `TG-DEMO-001`, `TG-DEMO-002`, and `TG-DEMO-003` **fail** against vulnerable endpoints.
- `TG-DEMO-004` through `TG-DEMO-008` **pass** against secure endpoints.
- The CLI may exit with code `1` because the demo intentionally contains findings.
- The automated test suite also verifies the demo flow using a local test server (`tests/test_demo_e2e.py`).

See [`examples/vulnerable-fastapi-app/README.md`](examples/vulnerable-fastapi-app/README.md) for curl examples.

## Reports

TenantGuard can write:

- **JSON** — machine-readable run results
- **Markdown** — human-readable findings for review and CI artifacts
- **HTML** — self-contained reports for local review in a browser

Example demo output:

- [`examples/reports/demo-report.example.md`](examples/reports/demo-report.example.md)
- [`examples/reports/demo-report.example.html`](examples/reports/demo-report.example.html)

HTML reports are self-contained files designed for local review and sharing with teams. They include the run summary, failed checks, passed checks, assertion details, and redacted request/response evidence.

Generate an HTML report:

```bash
tenantguard run examples/configs/tenantguard-demo.yml \
  --env examples/vulnerable-fastapi-app/.env.demo \
  --report html \
  --output reports/demo-report.html
```

Reports redact bearer tokens, cookie session values, and other sensitive values. Authorization and Cookie headers are redacted in report output.

Local report files are written under `reports/` by default. That directory is gitignored.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success — no findings at or above `--fail-on` |
| `1` | Findings detected at or above `--fail-on` |
| `2` | Invalid configuration |
| `3` | Safety confirmation required: public target without `--confirm-authorized-scope` |
| `4` | Target unavailable |
| `5` | Internal error |

## Development

```bash
pip install -e ".[dev,demo]"
ruff check .
mypy tenantguard
pytest
```

Validate example configs:

```bash
tenantguard validate examples/configs/tenantguard.basic.yml
tenantguard validate examples/configs/tenantguard-demo.yml
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## Roadmap

See [ROADMAP.md](ROADMAP.md).

## License

MIT. See [LICENSE](LICENSE).
