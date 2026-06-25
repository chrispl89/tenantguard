# TenantGuard Report

## Summary

- Project: TenantGuard Vulnerable FastAPI Demo
- Target: http://localhost:8000
- Started: 2026-01-01T12:00:00+00:00
- Finished: 2026-01-01T12:00:01+00:00
- Duration: 842.15 ms
- Total: 8
- Passed: 5
- Failed: 3
- Errors: 0
- Highest failed severity: critical

## Findings

### [CRITICAL] TG-DEMO-001 — Tenant A user cannot access Tenant B invoice through vulnerable endpoint

- Status: failed
- Actor: tenant_a_user
- Request: GET /vulnerable/invoices/inv_b_001
- Actual status code: 200
- Duration: 98.42 ms
- Error: none
- Failed assertions:
- status_in: Expected status in [403, 404], got 200.

Response snippet:

```
{"id":"inv_b_001","tenant_id":"tenant_b","customer_email":"bob@tenant-b.example","amount":2400,"marker":"TENANT_B_INVOICE_MARKER"}
```

### [HIGH] TG-DEMO-002 — Vulnerable customer list should not leak Tenant B customer marker

- Status: failed
- Actor: tenant_a_user
- Request: GET /vulnerable/customers
- Actual status code: 200
- Duration: 76.11 ms
- Error: none
- Failed assertions:
- body_not_contains: Body unexpectedly contains 'TENANT_B_CUSTOMER_MARKER'.

Response snippet:

```
[{"id":"cus_a_001","tenant_id":"tenant_a","email":"customer-a@tenant-a.example","marker":"TENANT_A_CUSTOMER_MARKER"},{"id":"cus_b_001","tenant_id":"tenant_b","email":"customer-b@tenant-b.example","marker":"TENANT_B_CUSTOMER_MARKER"}]
```

### [HIGH] TG-DEMO-003 — Regular Tenant A user cannot access vulnerable admin settings

- Status: failed
- Actor: tenant_a_user
- Request: GET /vulnerable/admin/settings
- Actual status code: 200
- Duration: 64.08 ms
- Error: none
- Failed assertions:
- status_in: Expected status in [403], got 200.

## Passed checks

| Check ID | Name | Severity | Status | Duration |
| --- | --- | --- | --- | --- |
| TG-DEMO-004 | Tenant A user cannot access Tenant B invoice through secure endpoint | critical | passed | 71.22 ms |
| TG-DEMO-005 | Secure customer list does not leak Tenant B marker | high | passed | 69.45 ms |
| TG-DEMO-006 | Regular Tenant A user cannot access secure admin settings | high | passed | 62.31 ms |
| TG-DEMO-007 | Tenant A admin can access secure admin settings | medium | passed | 58.90 ms |
| TG-DEMO-008 | Platform admin can access Tenant B invoice through secure endpoint | medium | passed | 61.77 ms |
