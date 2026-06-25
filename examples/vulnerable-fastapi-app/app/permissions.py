"""Authorization helpers for the secure demo endpoints."""

from __future__ import annotations

from fastapi import HTTPException, status

from app.models import CurrentUser


def is_platform_admin(user: CurrentUser) -> bool:
    return user.role == "platform_admin"


def can_access_tenant_resource(user: CurrentUser, resource_tenant_id: str) -> bool:
    if is_platform_admin(user):
        return True
    return user.tenant_id == resource_tenant_id


def require_admin(user: CurrentUser) -> None:
    if user.role not in {"admin", "platform_admin"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required.",
        )
