"""Data models for the demo application."""

from __future__ import annotations

from pydantic import BaseModel


class CurrentUser(BaseModel):
    id: str
    tenant_id: str
    role: str


class Invoice(BaseModel):
    id: str
    tenant_id: str
    customer_email: str
    amount: int
    marker: str


class Customer(BaseModel):
    id: str
    tenant_id: str
    email: str
    marker: str


class AdminSettings(BaseModel):
    tenant_id: str
    maintenance_mode: bool
    support_email: str


class AuditEvent(BaseModel):
    tenant_id: str
    event: str


class InvoiceUpdate(BaseModel):
    amount: int | None = None
    customer_email: str | None = None
