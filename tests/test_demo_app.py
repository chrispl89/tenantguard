"""Tests for the vulnerable FastAPI demo application."""

from __future__ import annotations

import pytest
from app.data import reset_demo_data
from app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)


@pytest.fixture(autouse=True)
def _reset_demo_data() -> None:
    reset_demo_data()

TENANT_A_USER = "demo-token-tenant-a-user"
TENANT_A_ADMIN = "demo-token-tenant-a-admin"
PLATFORM_ADMIN = "demo-token-platform-admin"


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_health_returns_200() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_missing_authorization_returns_401() -> None:
    response = client.get("/vulnerable/invoices/inv_a_001")
    assert response.status_code == 401


def test_tenant_a_user_can_access_own_vulnerable_invoice() -> None:
    response = client.get("/vulnerable/invoices/inv_a_001", headers=_auth(TENANT_A_USER))
    assert response.status_code == 200
    assert response.json()["marker"] == "TENANT_A_INVOICE_MARKER"


def test_tenant_a_user_can_access_foreign_vulnerable_invoice() -> None:
    response = client.get("/vulnerable/invoices/inv_b_001", headers=_auth(TENANT_A_USER))
    assert response.status_code == 200
    assert response.json()["marker"] == "TENANT_B_INVOICE_MARKER"


def test_tenant_a_user_cannot_access_foreign_secure_invoice() -> None:
    response = client.get("/secure/invoices/inv_b_001", headers=_auth(TENANT_A_USER))
    assert response.status_code == 404


def test_vulnerable_customer_list_leaks_tenant_b_marker() -> None:
    response = client.get("/vulnerable/customers", headers=_auth(TENANT_A_USER))
    assert response.status_code == 200
    body = response.text
    assert "TENANT_B_CUSTOMER_MARKER" in body
    assert "customer-b@tenant-b.example" in body


def test_secure_customer_list_does_not_leak_tenant_b_marker() -> None:
    response = client.get("/secure/customers", headers=_auth(TENANT_A_USER))
    assert response.status_code == 200
    body = response.text
    assert "TENANT_B_CUSTOMER_MARKER" not in body
    assert "customer-b@tenant-b.example" not in body


def test_tenant_a_user_can_access_vulnerable_admin_settings() -> None:
    response = client.get("/vulnerable/admin/settings", headers=_auth(TENANT_A_USER))
    assert response.status_code == 200


def test_tenant_a_user_cannot_access_secure_admin_settings() -> None:
    response = client.get("/secure/admin/settings", headers=_auth(TENANT_A_USER))
    assert response.status_code == 403


def test_tenant_a_admin_can_access_secure_admin_settings() -> None:
    response = client.get("/secure/admin/settings", headers=_auth(TENANT_A_ADMIN))
    assert response.status_code == 200
    assert "tenant_a" in response.text


def test_platform_admin_can_access_tenant_b_secure_invoice() -> None:
    response = client.get("/secure/invoices/inv_b_001", headers=_auth(PLATFORM_ADMIN))
    assert response.status_code == 200
    assert response.json()["marker"] == "TENANT_B_INVOICE_MARKER"


def test_vulnerable_patch_allows_cross_tenant_invoice_update() -> None:
    response = client.patch(
        "/vulnerable/invoices/inv_b_001",
        headers=_auth(TENANT_A_USER),
        json={"amount": 9999},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["marker"] == "TENANT_B_INVOICE_MARKER"
    assert body["amount"] == 9999
    assert body["tenant_id"] == "tenant_b"


def test_secure_patch_blocks_cross_tenant_invoice_update() -> None:
    response = client.patch(
        "/secure/invoices/inv_b_001",
        headers=_auth(TENANT_A_USER),
        json={"amount": 9999},
    )
    assert response.status_code == 404


def test_secure_patch_allows_tenant_a_admin_own_invoice_update() -> None:
    response = client.patch(
        "/secure/invoices/inv_a_001",
        headers=_auth(TENANT_A_ADMIN),
        json={"amount": 1234},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["tenant_id"] == "tenant_a"
    assert body["amount"] == 1234


def test_platform_admin_can_patch_tenant_b_invoice() -> None:
    response = client.patch(
        "/secure/invoices/inv_b_001",
        headers=_auth(PLATFORM_ADMIN),
        json={"amount": 4321},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["marker"] == "TENANT_B_INVOICE_MARKER"
    assert body["amount"] == 4321
