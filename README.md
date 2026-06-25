# TenantGuard

Config-driven authorization regression testing for multi-tenant SaaS APIs.

You define actors, tokens, known resources, HTTP requests, and expected results in YAML. TenantGuard executes those checks and reports pass/fail findings. It is especially useful after AI-generated CRUD endpoints pass happy-path tests but still miss tenant ownership checks.

## The problem

Multi-tenant SaaS APIs often look correct on the happy path — authentication works, CRUD tests pass — yet still allow:

- cross-tenant access by resource ID,
- foreign records in list endpoints,
- regular users to call admin routes.

Example vulnerable pattern (authentication without ownership check):

```python
@app.get("/api/invoices/{invoice_id}")
def get_invoice(invoice_id: str, user: User = Depends(get_current_user)):
    invoice = db.get_invoice(invoice_id)
    return invoice
```

TenantGuard catches that class of mistake before production.

## What TenantGuard is not

TenantGuard is **not** a vulnerability scanner. It does not crawl applications, discover endpoints, brute-force credentials, bypass rate limits, or run exploit payloads. You define every check explicitly.

## Responsible Use

- Use TenantGuard only on applications you own, maintain, or are explicitly authorized to test.
- Do not use it against third-party systems without written permission.
- Do not use it for brute force, credential attacks, rate-limit bypass, exploitation, or unauthorized scanning.

Unauthorized testing may be illegal and harmful. You are responsible for using this tool safely, legally, and ethically.

## Installation

TenantGuard is **not published to PyPI yet**. Install from this repository:

```bash
git clone https://github.com/chrispl89/tenantguard.git
cd tenantguard
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,demo]"
```

Core-only install (without demo app dependencies):

```bash
pip install -e .
```

Planned future installation:

```bash
pip install tenantguard
```

## Quickstart

### Run the included demo

**Terminal 1** — start the local FastAPI demo API:

```bash
cd examples/vulnerable-fastapi-app
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

**Terminal 2** — validate and generate an HTML report:

```bash
tenantguard validate examples/configs/tenantguard-demo.yml

tenantguard run examples/configs/tenantguard-demo.yml \
  --env examples/vulnerable-fastapi-app/.env.demo \
  --report html \
  --output reports/demo-report.html
```

Expected outcome:

- `TG-DEMO-001` through `TG-DEMO-003` **fail** against intentionally vulnerable endpoints.
- `TG-DEMO-004` through `TG-DEMO-008` **pass** against secure endpoints.
- The full demo may exit with code `1` because vulnerable checks are expected to fail.
- Run secure checks only with `--exclude vulnerable`.

See [Demo](#demo) for details and Docker as an alternative.

### Create your own config

```bash
tenantguard init
```

Edit `tenantguard.yml` and prefer `token_env` for secrets (not inline tokens). Then:

```bash
tenantguard validate tenantguard.yml
tenantguard run tenantguard.yml --env .env.local --dry-run
tenantguard run tenantguard.yml --env .env.local
```

A fuller static example: [`examples/configs/tenantguard.basic.yml`](examples/configs/tenantguard.basic.yml).

## Demo

The repository includes a local FastAPI app with intentionally vulnerable endpoints and secure variants for comparison. Use it only locally.

**Python (recommended):**

```bash
cd examples/vulnerable-fastapi-app
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

**Docker Compose (alternative):**

```bash
cd examples/vulnerable-fastapi-app
docker compose up --build
```

Run TenantGuard:

```bash
tenantguard run examples/configs/tenantguard-demo.yml \
  --env examples/vulnerable-fastapi-app/.env.demo \
  --report markdown \
  --output reports/demo-report.md
```

See [`examples/vulnerable-fastapi-app/README.md`](examples/vulnerable-fastapi-app/README.md) for curl examples. The automated test suite also verifies the demo flow (`tests/test_demo_e2e.py`).

## Configuration basics

TenantGuard configs define:

| Section | Purpose |
| --- | --- |
| `target.base_url` | API under test |
| `actors` | Users with bearer or cookie auth via `token_env` |
| `resources` | Known object IDs for templated paths |
| `checks` | HTTP requests and `expect` assertions |
| `safety` | Write-method blocking, request limits, redaction |

Minimal check:

```yaml
checks:
  - id: "TG-001"
    name: "Tenant A user cannot access Tenant B invoice"
    severity: "critical"
    actor: "tenant_a_user"
    request:
      method: "GET"
      path: "/api/invoices/{{ resources.tenant_b_invoice.id }}"
    expect:
      status_in: [403, 404]
```

## Authentication

### Bearer tokens

```yaml
actors:
  tenant_a_user:
    tenant_id: "tenant_a"
    role: "user"
    auth:
      type: "bearer"
      token_env: "TENANT_A_USER_TOKEN"
```

Store the token in a local `.env` file referenced by `--env`. Do not commit secrets.

### Cookie sessions

For session-cookie based applications:

```yaml
actors:
  client_a:
    tenant_id: "tenant_a"
    role: "client"
    auth:
      type: "cookie"
      cookie_name: "app_session"
      token_env: "CLIENT_A_SESSION"
```

This sends `Cookie: app_session=<value from CLIENT_A_SESSION>`. Example config: [`examples/configs/tenantguard.cookie-auth.yml`](examples/configs/tenantguard.cookie-auth.yml).

Do not paste real session cookies into public configs, reports, or issues.

## Reports

TenantGuard supports three report formats:

| Format | Use case |
| --- | --- |
| `json` | Machine-readable results for CI or tooling |
| `markdown` | Human-readable findings for review and artifacts |
| `html` | Self-contained browser report with redacted evidence |

```bash
tenantguard run tenantguard.yml --env .env.local --report json --output reports/report.json
tenantguard run tenantguard.yml --env .env.local --report markdown --output reports/report.md
tenantguard run tenantguard.yml --env .env.local --report html --output reports/report.html
```

Example demo outputs (synthetic data, redacted headers):

- [`examples/reports/demo-report.example.md`](examples/reports/demo-report.example.md)
- [`examples/reports/demo-report.example.html`](examples/reports/demo-report.example.html)

HTML reports are self-contained (no external CDN assets). Authorization and Cookie headers are redacted in all report formats.

Local report files are written under `reports/` by default. That directory is gitignored.

## Write-method checks

By default, TenantGuard blocks write-method checks (`POST`, `PUT`, `PATCH`, `DELETE`) when `safety.allow_write_methods` is `false`.

To run explicit write authorization checks, set `allow_write_methods: true`. Only do this against local or staging environments with test data you control.

```bash
tenantguard validate examples/configs/tenantguard-demo-write.yml

tenantguard run examples/configs/tenantguard-demo-write.yml \
  --env examples/vulnerable-fastapi-app/.env.demo \
  --report html \
  --output reports/demo-write-report.html
```

- `TG-WRITE-001` **fails** against the vulnerable PATCH endpoint (cross-tenant update succeeds when it should not).
- `TG-WRITE-002` through `TG-WRITE-004` **pass** against secure PATCH endpoints.
- Run secure write checks only with `--exclude vulnerable`.

## Check tags and list-checks

Optional `tags` organize larger authorization test suites. Tags filter explicit checks from your config — they do not discover endpoints or scan your application.

```yaml
checks:
  - id: AUTH-001
    name: "Tenant A user cannot access Tenant B invoice"
    severity: "critical"
    actor: "tenant_a_user"
    tags:
      - tenant-isolation
      - horizontal-access
      - read-only
    request:
      method: "GET"
      path: "/api/invoices/{{ resources.tenant_b_invoice.id }}"
    expect:
      status_in: [403, 404]
```

Filter by tag (repeatable; multiple values use OR semantics):

```bash
tenantguard run tenantguard.yml --tag tenant-isolation
tenantguard run tenantguard.yml --exclude-tag write
```

Filter order: `--include` → `--exclude` → `--tag` → `--exclude-tag`.

Inspect checks without tokens or HTTP requests:

```bash
tenantguard run tenantguard.yml --list-checks
```

`--list-checks` validates the config, applies filters, and prints a table. It does not resolve tokens, require environment variables, run safety checks, or send HTTP requests.

## CLI reference

```bash
tenantguard validate CONFIG [--env .env.local]
tenantguard run CONFIG [--env .env.local]

# Reports and CI exit behavior
tenantguard run CONFIG --env .env.local --report html --output reports/report.html
tenantguard run CONFIG --env .env.local --fail-on high

# Filter checks
tenantguard run CONFIG --include TG-001
tenantguard run CONFIG --exclude admin
tenantguard run CONFIG --tag tenant-isolation --exclude-tag write

# Preview without HTTP (dry-run still runs safety checks when tokens are available)
tenantguard run CONFIG --dry-run
tenantguard run CONFIG --tag tenant-isolation --dry-run

# Public targets require explicit confirmation
tenantguard run CONFIG --confirm-authorized-scope
```

## Supported assertions

TenantGuard evaluates these `expect` fields:

- `status_in`, `status_not_in`
- `body_contains`, `body_not_contains`
- `json_path_equals`, `json_path_not_equals`
- `header_exists`, `header_equals`
- `max_response_time_ms`

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success — no findings at or above `--fail-on` |
| `1` | Findings detected at or above `--fail-on` |
| `2` | Invalid configuration |
| `3` | Safety confirmation required (public target without `--confirm-authorized-scope`) |
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
tenantguard validate examples/configs/tenantguard.cookie-auth.yml
tenantguard validate examples/configs/tenantguard-demo-write.yml
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## Roadmap

See [ROADMAP.md](ROADMAP.md) for planned work (CSRF support, OpenAPI config helper, GitHub Action, PyPI packaging, pytest plugin).

## License

MIT. See [LICENSE](LICENSE).
