# TenantGuard Vulnerable FastAPI Demo

## What this is

This is a **local-only** demo application with intentionally vulnerable authorization endpoints and secure variants for comparison.

The demo app is intentionally vulnerable and should only be run locally for learning and testing TenantGuard.

Use it to see how TenantGuard detects:

- cross-tenant invoice access,
- customer list leakage,
- missing admin role checks.

## Responsible use

This demo is for local development and education only. Do not deploy it to production.

Do not use TenantGuard or this demo against systems you do not own or are not explicitly authorized to test.

All tokens in this demo are **synthetic demo tokens**. They are not secrets and exist only for local testing.

## Run with Docker Compose

```bash
cd examples/vulnerable-fastapi-app
docker compose up --build
```

## Run without Docker

From this directory, with demo dependencies installed:

```bash
pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

## Health check

```bash
curl http://localhost:8000/health
```

## Example vulnerable request

```bash
curl -H "Authorization: Bearer demo-token-tenant-a-user" \
  http://localhost:8000/vulnerable/invoices/inv_b_001
```

This intentionally returns Tenant B invoice data to a Tenant A user. The vulnerable endpoint checks authentication only, not tenant ownership.

## Example secure request

```bash
curl -H "Authorization: Bearer demo-token-tenant-a-user" \
  http://localhost:8000/secure/invoices/inv_b_001
```

This should return `404 Not Found` because the secure endpoint verifies tenant ownership.

## Run TenantGuard

From the repository root:

```bash
tenantguard run examples/configs/tenantguard-demo.yml \
  --env examples/vulnerable-fastapi-app/.env.demo \
  --report markdown \
  --output reports/demo-report.md
```

## Expected results

- `TG-DEMO-001`, `TG-DEMO-002`, and `TG-DEMO-003` are expected to **fail** (vulnerable endpoints).
- `TG-DEMO-004` through `TG-DEMO-008` are expected to **pass** (secure endpoints).
- The CLI may exit with code `1` because the demo intentionally includes failing checks.
- A Markdown report is written locally to `reports/demo-report.md` (gitignored).

See also the committed example report at [`examples/reports/demo-report.example.md`](../reports/demo-report.example.md).
