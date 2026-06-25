"""Minimal placeholder substitution for request paths."""

from __future__ import annotations

import re

from tenantguard.config import ConfigValidationError, TenantGuardConfig

RESOURCE_PLACEHOLDER = re.compile(
    r"\{\{\s*resources\.([a-zA-Z0-9_]+)\.id\s*\}\}"
)
ACTOR_PLACEHOLDER = re.compile(
    r"\{\{\s*actors\.([a-zA-Z0-9_]+)\.tenant_id\s*\}\}"
)


def render_path(path: str, config: TenantGuardConfig) -> str:
    """Substitute supported placeholders in a request path."""
    rendered = path

    for match in RESOURCE_PLACEHOLDER.finditer(path):
        key = match.group(1)
        if key not in config.resources:
            msg = f"Unknown resource placeholder: resources.{key}.id"
            raise ConfigValidationError(msg)
        rendered = rendered.replace(match.group(0), config.resources[key].id)

    for match in ACTOR_PLACEHOLDER.finditer(path):
        key = match.group(1)
        if key not in config.actors:
            msg = f"Unknown actor placeholder: actors.{key}.tenant_id"
            raise ConfigValidationError(msg)
        rendered = rendered.replace(match.group(0), config.actors[key].tenant_id)

    return rendered
