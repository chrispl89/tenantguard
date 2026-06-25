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


def render_path(
    path: str,
    config: TenantGuardConfig,
    *,
    check_id: str | None = None,
) -> str:
    """Substitute supported placeholders in a request path."""
    rendered = path
    check_prefix = f"Check {check_id} " if check_id else "Check "

    for match in RESOURCE_PLACEHOLDER.finditer(path):
        key = match.group(1)
        if key not in config.resources:
            available = ", ".join(sorted(config.resources))
            msg = (
                f'{check_prefix}references unknown resource "{key}". '
                f"Available resources: {available}."
            )
            raise ConfigValidationError(msg)
        rendered = rendered.replace(match.group(0), config.resources[key].id)

    for match in ACTOR_PLACEHOLDER.finditer(path):
        key = match.group(1)
        if key not in config.actors:
            available = ", ".join(sorted(config.actors))
            msg = (
                f'{check_prefix}references unknown actor "{key}" in template. '
                f"Available actors: {available}."
            )
            raise ConfigValidationError(msg)
        rendered = rendered.replace(match.group(0), config.actors[key].tenant_id)

    return rendered
