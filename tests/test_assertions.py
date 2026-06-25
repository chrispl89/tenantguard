"""Tests for HTTP response assertions."""

from __future__ import annotations

import httpx

from tenantguard.checks.assertions import evaluate_expectations
from tenantguard.checks.severity import Severity
from tenantguard.config import CheckConfig, ExpectConfig, RequestConfig
from tenantguard.results import AssertionStatus


def _check(expect: ExpectConfig) -> CheckConfig:
    return CheckConfig(
        id="TG-001",
        name="Example",
        severity=Severity.HIGH,
        actor="tenant_a_user",
        request=RequestConfig(method="GET", path="/api/items"),
        expect=expect,
    )


def _response(
    *,
    status_code: int = 200,
    text: str = "",
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    return httpx.Response(
        status_code=status_code,
        text=text,
        headers=headers or {},
        request=httpx.Request("GET", "http://localhost/api/items"),
    )


def test_status_in_passes() -> None:
    results = evaluate_expectations(
        _check(ExpectConfig(status_in=[200, 404])),
        _response(status_code=200),
        elapsed_ms=10.0,
        secrets=[],
    )
    assert results[0].status == AssertionStatus.PASSED


def test_status_in_fails() -> None:
    results = evaluate_expectations(
        _check(ExpectConfig(status_in=[403, 404])),
        _response(status_code=200),
        elapsed_ms=10.0,
        secrets=[],
    )
    assert results[0].status == AssertionStatus.FAILED


def test_status_not_in_passes_and_fails() -> None:
    passed = evaluate_expectations(
        _check(ExpectConfig(status_not_in=[500])),
        _response(status_code=200),
        elapsed_ms=10.0,
        secrets=[],
    )
    failed = evaluate_expectations(
        _check(ExpectConfig(status_not_in=[200])),
        _response(status_code=200),
        elapsed_ms=10.0,
        secrets=[],
    )
    assert passed[0].status == AssertionStatus.PASSED
    assert failed[0].status == AssertionStatus.FAILED


def test_body_contains_passes_and_fails() -> None:
    passed = evaluate_expectations(
        _check(ExpectConfig(body_contains=["tenant_b"])),
        _response(text='{"tenant":"tenant_b"}'),
        elapsed_ms=10.0,
        secrets=[],
    )
    failed = evaluate_expectations(
        _check(ExpectConfig(body_contains=["tenant_b"])),
        _response(text='{"tenant":"tenant_a"}'),
        elapsed_ms=10.0,
        secrets=[],
    )
    assert passed[0].status == AssertionStatus.PASSED
    assert failed[0].status == AssertionStatus.FAILED


def test_body_not_contains_passes_and_fails() -> None:
    passed = evaluate_expectations(
        _check(ExpectConfig(body_not_contains=["tenant_b"])),
        _response(text='{"tenant":"tenant_a"}'),
        elapsed_ms=10.0,
        secrets=[],
    )
    failed = evaluate_expectations(
        _check(ExpectConfig(body_not_contains=["tenant_b"])),
        _response(text='{"tenant":"tenant_b"}'),
        elapsed_ms=10.0,
        secrets=[],
    )
    assert passed[0].status == AssertionStatus.PASSED
    assert failed[0].status == AssertionStatus.FAILED


def test_json_path_equals_passes_and_fails() -> None:
    passed = evaluate_expectations(
        _check(ExpectConfig(json_path_equals={"$.tenant_id": "tenant_a"})),
        _response(text='{"tenant_id":"tenant_a"}'),
        elapsed_ms=10.0,
        secrets=[],
    )
    failed = evaluate_expectations(
        _check(ExpectConfig(json_path_equals={"$.tenant_id": "tenant_a"})),
        _response(text='{"tenant_id":"tenant_b"}'),
        elapsed_ms=10.0,
        secrets=[],
    )
    assert passed[0].status == AssertionStatus.PASSED
    assert failed[0].status == AssertionStatus.FAILED


def test_json_path_not_equals_passes_and_fails() -> None:
    passed = evaluate_expectations(
        _check(ExpectConfig(json_path_not_equals={"$.tenant_id": "tenant_b"})),
        _response(text='{"tenant_id":"tenant_a"}'),
        elapsed_ms=10.0,
        secrets=[],
    )
    failed = evaluate_expectations(
        _check(ExpectConfig(json_path_not_equals={"$.tenant_id": "tenant_b"})),
        _response(text='{"tenant_id":"tenant_b"}'),
        elapsed_ms=10.0,
        secrets=[],
    )
    assert passed[0].status == AssertionStatus.PASSED
    assert failed[0].status == AssertionStatus.FAILED


def test_json_path_on_non_json_body_errors() -> None:
    results = evaluate_expectations(
        _check(ExpectConfig(json_path_equals={"$.tenant_id": "tenant_a"})),
        _response(text="not-json"),
        elapsed_ms=10.0,
        secrets=[],
    )
    assert results[0].status == AssertionStatus.ERROR
    assert "not valid JSON" in results[0].message


def test_header_exists_passes_and_fails() -> None:
    passed = evaluate_expectations(
        _check(ExpectConfig(header_exists=["content-type"])),
        _response(headers={"content-type": "application/json"}),
        elapsed_ms=10.0,
        secrets=[],
    )
    failed = evaluate_expectations(
        _check(ExpectConfig(header_exists=["x-tenant-id"])),
        _response(headers={"content-type": "application/json"}),
        elapsed_ms=10.0,
        secrets=[],
    )
    assert passed[0].status == AssertionStatus.PASSED
    assert failed[0].status == AssertionStatus.FAILED


def test_header_equals_passes_and_fails() -> None:
    passed = evaluate_expectations(
        _check(ExpectConfig(header_equals={"content-type": "application/json"})),
        _response(headers={"content-type": "application/json"}),
        elapsed_ms=10.0,
        secrets=[],
    )
    failed = evaluate_expectations(
        _check(ExpectConfig(header_equals={"content-type": "text/plain"})),
        _response(headers={"content-type": "application/json"}),
        elapsed_ms=10.0,
        secrets=[],
    )
    assert passed[0].status == AssertionStatus.PASSED
    assert failed[0].status == AssertionStatus.FAILED


def test_max_response_time_ms_passes_and_fails() -> None:
    passed = evaluate_expectations(
        _check(ExpectConfig(max_response_time_ms=100)),
        _response(),
        elapsed_ms=50.0,
        secrets=[],
    )
    failed = evaluate_expectations(
        _check(ExpectConfig(max_response_time_ms=100)),
        _response(),
        elapsed_ms=150.0,
        secrets=[],
    )
    assert passed[0].status == AssertionStatus.PASSED
    assert failed[0].status == AssertionStatus.FAILED


def test_secrets_redacted_in_assertion_messages() -> None:
    results = evaluate_expectations(
        _check(ExpectConfig(body_contains=["super-secret-token"])),
        _response(text="response with super-secret-token"),
        elapsed_ms=10.0,
        secrets=["super-secret-token"],
    )
    assert results[0].status == AssertionStatus.PASSED
    assert "super-secret-token" not in results[0].message
    assert "<redacted>" in results[0].message
