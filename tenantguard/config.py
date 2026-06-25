"""Configuration models and validation."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from tenantguard.checks.severity import Severity
from tenantguard.models import RuntimeContext

ALLOWED_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class ConfigValidationError(Exception):
    """Raised when configuration structure or references are invalid."""


class ProjectConfig(BaseModel):
    name: str = "TenantGuard checks"
    description: str | None = None


class TargetConfig(BaseModel):
    base_url: str
    authorized: bool = False

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"}:
            msg = "target.base_url must use http or https"
            raise ValueError(msg)
        if not parsed.hostname:
            msg = "target.base_url must include a host"
            raise ValueError(msg)
        return value


class SafetyConfig(BaseModel):
    allow_write_methods: bool = False
    confirm_authorized_scope: bool = True
    max_requests_per_run: int = 100
    request_delay_ms: int = 100
    redact_sensitive_values: bool = True


class HttpConfig(BaseModel):
    timeout_seconds: int = 10
    verify_tls: bool = True
    user_agent: str = "TenantGuard/0.1.0 authorization-regression-tester"
    default_headers: dict[str, str] = Field(default_factory=dict)


class AuthConfig(BaseModel):
    type: Literal["bearer"] = "bearer"
    token: str | None = None
    token_env: str | None = None

    @model_validator(mode="after")
    def validate_token_source(self) -> AuthConfig:
        if self.token and self.token_env:
            msg = "auth must use either token or token_env, not both"
            raise ValueError(msg)
        if not self.token and not self.token_env:
            msg = "auth must define token or token_env"
            raise ValueError(msg)
        return self

    def __repr__(self) -> str:
        if self.token_env:
            return f"AuthConfig(type={self.type!r}, token_env={self.token_env!r})"
        return f"AuthConfig(type={self.type!r}, token=<redacted>)"


class ActorConfig(BaseModel):
    label: str | None = None
    tenant_id: str
    role: str
    auth: AuthConfig

    def __repr__(self) -> str:
        label = f", label={self.label!r}" if self.label else ""
        return (
            f"ActorConfig(tenant_id={self.tenant_id!r}, role={self.role!r}{label}, "
            f"auth={self.auth!r})"
        )


class ResourceConfig(BaseModel):
    type: str
    id: str
    tenant_id: str
    owner_actor: str | None = None
    forbidden_markers: list[str] = Field(default_factory=list)


class RequestConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    method: str
    path: str
    headers: dict[str, str] = Field(default_factory=dict)
    body_json: dict[str, Any] | None = Field(default=None, alias="json")

    @field_validator("method")
    @classmethod
    def validate_method(cls, value: str) -> str:
        normalized = value.upper()
        if normalized not in ALLOWED_METHODS:
            allowed = ", ".join(sorted(ALLOWED_METHODS))
            msg = f"Unsupported HTTP method {value!r}. Allowed methods: {allowed}"
            raise ValueError(msg)
        return normalized


class ExpectConfig(BaseModel):
    status_in: list[int] | None = None
    status_not_in: list[int] | None = None
    body_contains: list[str] | None = None
    body_not_contains: list[str] | None = None
    json_path_equals: dict[str, Any] | None = None
    json_path_not_equals: dict[str, Any] | None = None
    header_exists: list[str] | None = None
    header_equals: dict[str, str] | None = None
    max_response_time_ms: int | None = None


class CheckConfig(BaseModel):
    id: str
    name: str
    description: str | None = None
    severity: Severity
    actor: str
    request: RequestConfig
    expect: ExpectConfig


class TenantGuardConfig(BaseModel):
    version: str = "0.1"
    project: ProjectConfig = Field(default_factory=ProjectConfig)
    target: TargetConfig
    safety: SafetyConfig = Field(default_factory=SafetyConfig)
    http: HttpConfig = Field(default_factory=HttpConfig)
    actors: dict[str, ActorConfig]
    resources: dict[str, ResourceConfig] = Field(default_factory=dict)
    checks: list[CheckConfig]


def load_config(path: Path) -> TenantGuardConfig:
    """Load and validate a TenantGuard YAML configuration file."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        msg = f"Configuration file must contain a YAML mapping: {path}"
        raise ConfigValidationError(msg)
    try:
        return TenantGuardConfig.model_validate(raw)
    except Exception as exc:
        msg = f"Invalid configuration: {exc}"
        raise ConfigValidationError(msg) from exc


def validate_config_structure(config: TenantGuardConfig) -> None:
    """Validate cross-field references and uniqueness constraints."""
    seen_ids: set[str] = set()
    for check in config.checks:
        if check.id in seen_ids:
            msg = f"Duplicate check id: {check.id}"
            raise ConfigValidationError(msg)
        seen_ids.add(check.id)
        if check.actor not in config.actors:
            msg = f"Check {check.id!r} references unknown actor: {check.actor!r}"
            raise ConfigValidationError(msg)


def validate_token_env(
    config: TenantGuardConfig,
    env: dict[str, str],
    *,
    required: bool,
) -> None:
    """Ensure token_env variables are present when required."""
    if not required:
        return
    missing: list[str] = []
    for actor_id, actor in config.actors.items():
        if actor.auth.token_env and actor.auth.token_env not in env:
            missing.append(f"{actor_id} ({actor.auth.token_env})")
    if missing:
        msg = "Missing environment variables for token_env: " + ", ".join(missing)
        raise ConfigValidationError(msg)


def resolve_tokens(config: TenantGuardConfig, env: dict[str, str]) -> RuntimeContext:
    """Resolve actor tokens into a separate runtime context."""
    tokens: dict[str, str] = {}
    for actor_id, actor in config.actors.items():
        if actor.auth.token is not None:
            tokens[actor_id] = actor.auth.token
        elif actor.auth.token_env is not None:
            var_name = actor.auth.token_env
            if var_name not in env or not env[var_name]:
                msg = f"Missing environment variable for actor {actor_id!r}: {var_name}"
                raise ConfigValidationError(msg)
            tokens[actor_id] = env[var_name]
    return RuntimeContext(actor_tokens=tokens)


def load_env_file(env_path: Path | None) -> dict[str, str]:
    """Load environment variables from a .env file and the current process env."""
    merged = dict(os.environ)
    if env_path is None:
        return merged
    if not env_path.exists():
        msg = f"Environment file not found: {env_path}"
        raise ConfigValidationError(msg)
    for line in env_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        merged[key.strip()] = value.strip().strip('"').strip("'")
    return merged


def warn_inline_tokens(config: TenantGuardConfig) -> list[str]:
    """Return actor ids that use inline bearer tokens."""
    return [actor_id for actor_id, actor in config.actors.items() if actor.auth.token is not None]


def collect_secrets(config: TenantGuardConfig, runtime: RuntimeContext | None = None) -> list[str]:
    """Collect secret values for redaction."""
    secrets: list[str] = []
    for actor in config.actors.values():
        if actor.auth.token:
            secrets.append(actor.auth.token)
    if runtime is not None:
        secrets.extend(runtime.actor_tokens.values())
    return [secret for secret in secrets if secret]
