"""FastAPI demo app with intentionally vulnerable and secure authorization endpoints."""

from __future__ import annotations

from fastapi import Depends, FastAPI, HTTPException, status

from app.auth import get_current_user
from app.data import (
    get_admin_settings,
    get_invoice,
    list_customers,
    list_customers_for_tenant,
    update_invoice,
)
from app.models import CurrentUser, InvoiceUpdate
from app.permissions import can_access_tenant_resource, is_platform_admin, require_admin

app = FastAPI(
    title="TenantGuard Vulnerable Demo API",
    description="Local demo app with intentionally vulnerable authorization examples.",
    version="0.1.0",
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/vulnerable/invoices/{invoice_id}")
def get_invoice_vulnerable(
    invoice_id: str,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, object]:
    # Vulnerable on purpose: this endpoint authenticates the user but does not verify
    # tenant ownership of the invoice.
    invoice = get_invoice(invoice_id)
    if invoice is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invoice not found.")
    return invoice.model_dump()


@app.get("/vulnerable/customers")
def list_customers_vulnerable(
    user: CurrentUser = Depends(get_current_user),
) -> list[dict[str, object]]:
    # Vulnerable on purpose: returns all customers without tenant filtering.
    return [customer.model_dump() for customer in list_customers()]


@app.patch("/vulnerable/invoices/{invoice_id}")
def patch_invoice_vulnerable(
    invoice_id: str,
    payload: InvoiceUpdate,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, object]:
    # Vulnerable on purpose: allows updating any invoice without tenant ownership checks.
    invoice = update_invoice(
        invoice_id,
        amount=payload.amount,
        customer_email=payload.customer_email,
    )
    if invoice is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invoice not found.")
    return invoice.model_dump()


@app.get("/vulnerable/admin/settings")
def get_admin_settings_vulnerable(
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, object]:
    # Vulnerable on purpose: any authenticated user can read admin settings.
    settings = get_admin_settings(user.tenant_id)
    if settings is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Settings not found.")
    return settings.model_dump()


@app.get("/secure/invoices/{invoice_id}")
def get_invoice_secure(
    invoice_id: str,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, object]:
    # Secure variant: verify the resource tenant before returning data.
    invoice = get_invoice(invoice_id)
    if invoice is None or not can_access_tenant_resource(user, invoice.tenant_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invoice not found.")
    return invoice.model_dump()


@app.get("/secure/customers")
def list_customers_secure(
    user: CurrentUser = Depends(get_current_user),
) -> list[dict[str, object]]:
    # Secure variant: return only customers for the authenticated tenant.
    if is_platform_admin(user):
        customers = list_customers()
    else:
        customers = list_customers_for_tenant(user.tenant_id)
    return [customer.model_dump() for customer in customers]


@app.patch("/secure/invoices/{invoice_id}")
def patch_invoice_secure(
    invoice_id: str,
    payload: InvoiceUpdate,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, object]:
    # Secure variant: only allow updates within the user's tenant unless platform admin.
    invoice = get_invoice(invoice_id)
    if invoice is None or not can_access_tenant_resource(user, invoice.tenant_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invoice not found.")
    updated = update_invoice(
        invoice_id,
        amount=payload.amount,
        customer_email=payload.customer_email,
    )
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invoice not found.")
    return updated.model_dump()


@app.get("/secure/admin/settings")
def get_admin_settings_secure(
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, object]:
    # Secure variant: admin role required for tenant settings.
    if is_platform_admin(user):
        settings = get_admin_settings("tenant_a")
    else:
        require_admin(user)
        settings = get_admin_settings(user.tenant_id)
    if settings is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Settings not found.")
    return settings.model_dump()
