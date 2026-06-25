"""Run result models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from tenantguard.checks.severity import Severity


class AssertionStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


class CheckStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass(slots=True)
class AssertionResult:
    name: str
    status: AssertionStatus
    message: str
    expected: Any | None = None
    actual: Any | None = None


@dataclass(slots=True)
class RequestSnapshot:
    method: str
    url: str
    path: str
    actor: str
    headers: dict[str, str]
    json_body: Any | None = None


@dataclass(slots=True)
class ResponseSnapshot:
    status_code: int | None
    headers: dict[str, str]
    body_snippet: str | None
    elapsed_ms: float | None


@dataclass(slots=True)
class CheckResult:
    id: str
    name: str
    severity: Severity
    actor: str
    status: CheckStatus
    request: RequestSnapshot
    response: ResponseSnapshot | None
    assertions: list[AssertionResult]
    error_message: str | None
    started_at: datetime
    finished_at: datetime
    elapsed_ms: float


@dataclass(slots=True)
class RunSummary:
    total: int
    passed: int
    failed: int
    errors: int
    skipped: int
    highest_failed_severity: Severity | None = None


@dataclass(slots=True)
class RunResult:
    project_name: str
    target_base_url: str
    started_at: datetime
    finished_at: datetime
    elapsed_ms: float
    checks: list[CheckResult] = field(default_factory=list)
    summary: RunSummary = field(
        default_factory=lambda: RunSummary(
            total=0, passed=0, failed=0, errors=0, skipped=0
        )
    )
