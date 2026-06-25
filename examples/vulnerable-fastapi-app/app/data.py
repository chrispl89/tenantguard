"""In-memory demo data store."""

from __future__ import annotations

from copy import deepcopy

from app.models import AdminSettings, AuditEvent, Customer, Invoice

USERS_BY_TOKEN: dict[str, dict[str, str]] = {
    "demo-token-tenant-a-user": {
        "id": "user_a_001",
        "tenant_id": "tenant_a",
        "role": "user",
    },
    "demo-token-tenant-a-admin": {
        "id": "admin_a_001",
        "tenant_id": "tenant_a",
        "role": "admin",
    },
    "demo-token-tenant-b-user": {
        "id": "user_b_001",
        "tenant_id": "tenant_b",
        "role": "user",
    },
    "demo-token-platform-admin": {
        "id": "platform_admin_001",
        "tenant_id": "platform",
        "role": "platform_admin",
    },
}

INVOICES: dict[str, Invoice] = {
    "inv_a_001": Invoice(
        id="inv_a_001",
        tenant_id="tenant_a",
        customer_email="alice@tenant-a.example",
        amount=1200,
        marker="TENANT_A_INVOICE_MARKER",
    ),
    "inv_b_001": Invoice(
        id="inv_b_001",
        tenant_id="tenant_b",
        customer_email="bob@tenant-b.example",
        amount=2400,
        marker="TENANT_B_INVOICE_MARKER",
    ),
}

CUSTOMERS: dict[str, Customer] = {
    "cus_a_001": Customer(
        id="cus_a_001",
        tenant_id="tenant_a",
        email="customer-a@tenant-a.example",
        marker="TENANT_A_CUSTOMER_MARKER",
    ),
    "cus_b_001": Customer(
        id="cus_b_001",
        tenant_id="tenant_b",
        email="customer-b@tenant-b.example",
        marker="TENANT_B_CUSTOMER_MARKER",
    ),
}

ADMIN_SETTINGS: dict[str, AdminSettings] = {
    "tenant_a": AdminSettings(
        tenant_id="tenant_a",
        maintenance_mode=False,
        support_email="support-a@tenant-a.example",
    ),
    "tenant_b": AdminSettings(
        tenant_id="tenant_b",
        maintenance_mode=False,
        support_email="support-b@tenant-b.example",
    ),
}

AUDIT_LOG: list[AuditEvent] = [
    AuditEvent(tenant_id="tenant_a", event="invoice_viewed:inv_a_001"),
    AuditEvent(tenant_id="tenant_b", event="invoice_viewed:inv_b_001"),
]


def get_invoice(invoice_id: str) -> Invoice | None:
    invoice = INVOICES.get(invoice_id)
    return deepcopy(invoice) if invoice else None


def list_customers() -> list[Customer]:
    return [deepcopy(customer) for customer in CUSTOMERS.values()]


def list_customers_for_tenant(tenant_id: str) -> list[Customer]:
    return [
        deepcopy(customer)
        for customer in CUSTOMERS.values()
        if customer.tenant_id == tenant_id
    ]


def get_admin_settings(tenant_id: str) -> AdminSettings | None:
    settings = ADMIN_SETTINGS.get(tenant_id)
    return deepcopy(settings) if settings else None


def update_invoice(
    invoice_id: str,
    *,
    amount: int | None,
    customer_email: str | None,
) -> Invoice | None:
    invoice = INVOICES.get(invoice_id)
    if invoice is None:
        return None
    if amount is not None:
        invoice.amount = amount
    if customer_email is not None:
        invoice.customer_email = customer_email
    return deepcopy(invoice)
