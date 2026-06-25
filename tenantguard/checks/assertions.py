"""HTTP response assertion evaluation."""

from __future__ import annotations

import json
from typing import Any

import httpx
from jsonpath_ng.ext import parse as parse_jsonpath

from tenantguard.config import CheckConfig, ExpectConfig
from tenantguard.results import AssertionResult, AssertionStatus
from tenantguard.safety import redact_secrets

BODY_SNIPPET_LIMIT = 1000


def _redact(value: Any, secrets: list[str]) -> Any:
    if isinstance(value, str):
        return redact_secrets(value, secrets)
    return value


def _response_body_text(response: httpx.Response) -> str:
    return response.text or ""


def _parse_json_body(
    response: httpx.Response,
) -> tuple[dict[str, Any] | list[Any] | None, str | None]:
    text = _response_body_text(response)
    if not text.strip():
        return None, "Response body is empty."
    try:
        parsed = response.json()
    except json.JSONDecodeError:
        return None, "Response body is not valid JSON."
    if not isinstance(parsed, (dict, list)):
        return None, "Response JSON root must be an object or array."
    return parsed, None


def _evaluate_json_path(
    path_expr: str,
    document: dict[str, Any] | list[Any],
) -> tuple[Any | None, str | None]:
    try:
        expression = parse_jsonpath(path_expr)
    except Exception as exc:
        return None, f"Invalid JSONPath expression {path_expr!r}: {exc}"
    matches = expression.find(document)
    if not matches:
        return None, f"JSONPath {path_expr!r} matched no values."
    return matches[0].value, None


def evaluate_expectations(
    check: CheckConfig,
    response: httpx.Response,
    *,
    elapsed_ms: float,
    secrets: list[str],
) -> list[AssertionResult]:
    """Evaluate all configured expectations for a check."""
    expect = check.expect
    results: list[AssertionResult] = []

    if expect.status_in is not None:
        actual = response.status_code
        passed = actual in expect.status_in
        results.append(
            AssertionResult(
                name="status_in",
                status=AssertionStatus.PASSED if passed else AssertionStatus.FAILED,
                message="Status code is in the expected set."
                if passed
                else f"Expected status in {expect.status_in}, got {actual}.",
                expected=expect.status_in,
                actual=actual,
            )
        )

    if expect.status_not_in is not None:
        actual = response.status_code
        passed = actual not in expect.status_not_in
        results.append(
            AssertionResult(
                name="status_not_in",
                status=AssertionStatus.PASSED if passed else AssertionStatus.FAILED,
                message="Status code is not in the forbidden set."
                if passed
                else f"Expected status not in {expect.status_not_in}, got {actual}.",
                expected=expect.status_not_in,
                actual=actual,
            )
        )

    body_text = _response_body_text(response)

    if expect.body_contains is not None:
        for needle in expect.body_contains:
            redacted_needle = redact_secrets(needle, secrets)
            passed = needle in body_text
            results.append(
                AssertionResult(
                    name="body_contains",
                    status=AssertionStatus.PASSED if passed else AssertionStatus.FAILED,
                    message=f"Body contains {redacted_needle!r}."
                    if passed
                    else f"Body does not contain {redacted_needle!r}.",
                    expected=redacted_needle,
                    actual=_redact(body_text[:BODY_SNIPPET_LIMIT], secrets) if body_text else None,
                )
            )

    if expect.body_not_contains is not None:
        for needle in expect.body_not_contains:
            redacted_needle = redact_secrets(needle, secrets)
            passed = needle not in body_text
            results.append(
                AssertionResult(
                    name="body_not_contains",
                    status=AssertionStatus.PASSED if passed else AssertionStatus.FAILED,
                    message=f"Body does not contain {redacted_needle!r}."
                    if passed
                    else f"Body unexpectedly contains {redacted_needle!r}.",
                    expected=redacted_needle,
                    actual=_redact(body_text[:BODY_SNIPPET_LIMIT], secrets) if body_text else None,
                )
            )

    if expect.json_path_equals is not None:
        document, error = _parse_json_body(response)
        for path_expr, expected_value in expect.json_path_equals.items():
            if error is not None:
                results.append(
                    AssertionResult(
                        name="json_path_equals",
                        status=AssertionStatus.ERROR,
                        message=error,
                        expected={path_expr: expected_value},
                        actual=None,
                    )
                )
                continue
            assert document is not None
            actual_value, path_error = _evaluate_json_path(path_expr, document)
            if path_error is not None:
                results.append(
                    AssertionResult(
                        name="json_path_equals",
                        status=AssertionStatus.ERROR,
                        message=path_error,
                        expected={path_expr: expected_value},
                        actual=None,
                    )
                )
                continue
            passed = actual_value == expected_value
            results.append(
                AssertionResult(
                    name="json_path_equals",
                    status=AssertionStatus.PASSED if passed else AssertionStatus.FAILED,
                    message=f"{path_expr} equals expected value."
                    if passed
                    else f"{path_expr} expected {expected_value!r}, got {actual_value!r}.",
                    expected={path_expr: expected_value},
                    actual={path_expr: _redact(actual_value, secrets)},
                )
            )

    if expect.json_path_not_equals is not None:
        document, error = _parse_json_body(response)
        for path_expr, forbidden_value in expect.json_path_not_equals.items():
            if error is not None:
                results.append(
                    AssertionResult(
                        name="json_path_not_equals",
                        status=AssertionStatus.ERROR,
                        message=error,
                        expected={path_expr: forbidden_value},
                        actual=None,
                    )
                )
                continue
            assert document is not None
            actual_value, path_error = _evaluate_json_path(path_expr, document)
            if path_error is not None:
                results.append(
                    AssertionResult(
                        name="json_path_not_equals",
                        status=AssertionStatus.ERROR,
                        message=path_error,
                        expected={path_expr: forbidden_value},
                        actual=None,
                    )
                )
                continue
            passed = actual_value != forbidden_value
            results.append(
                AssertionResult(
                    name="json_path_not_equals",
                    status=AssertionStatus.PASSED if passed else AssertionStatus.FAILED,
                    message=f"{path_expr} does not equal forbidden value."
                    if passed
                    else f"{path_expr} unexpectedly equals {forbidden_value!r}.",
                    expected={path_expr: forbidden_value},
                    actual={path_expr: _redact(actual_value, secrets)},
                )
            )

    if expect.header_exists is not None:
        response_headers = {key.lower(): value for key, value in response.headers.items()}
        for header_name in expect.header_exists:
            passed = header_name.lower() in response_headers
            results.append(
                AssertionResult(
                    name="header_exists",
                    status=AssertionStatus.PASSED if passed else AssertionStatus.FAILED,
                    message=f"Header {header_name!r} exists."
                    if passed
                    else f"Header {header_name!r} is missing.",
                    expected=header_name,
                    actual=list(response.headers.keys()),
                )
            )

    if expect.header_equals is not None:
        response_headers = {key.lower(): value for key, value in response.headers.items()}
        for header_name, expected_value in expect.header_equals.items():
            actual_value = response_headers.get(header_name.lower())
            passed = actual_value == expected_value
            results.append(
                AssertionResult(
                    name="header_equals",
                    status=AssertionStatus.PASSED if passed else AssertionStatus.FAILED,
                    message=f"Header {header_name!r} equals expected value."
                    if passed
                    else (
                        f"Header {header_name!r} expected {expected_value!r}, "
                        f"got {actual_value!r}."
                    ),
                    expected={header_name: expected_value},
                    actual={header_name: actual_value},
                )
            )

    if expect.max_response_time_ms is not None:
        passed = elapsed_ms <= expect.max_response_time_ms
        results.append(
            AssertionResult(
                name="max_response_time_ms",
                status=AssertionStatus.PASSED if passed else AssertionStatus.FAILED,
                message="Response time is within the limit."
                if passed
                else (
                    f"Response time {elapsed_ms:.2f}ms exceeds limit "
                    f"{expect.max_response_time_ms}ms."
                ),
                expected=expect.max_response_time_ms,
                actual=round(elapsed_ms, 2),
            )
        )

    return results


def has_assertion_failures(results: list[AssertionResult]) -> bool:
    """Return True when any assertion failed or errored."""
    return any(
        result.status in {AssertionStatus.FAILED, AssertionStatus.ERROR}
        for result in results
    )


def assertion_count(expect: ExpectConfig) -> int:
    """Count how many assertions are configured."""
    count = 0
    for field_name in (
        "status_in",
        "status_not_in",
        "body_contains",
        "body_not_contains",
        "json_path_equals",
        "json_path_not_equals",
        "header_exists",
        "header_equals",
        "max_response_time_ms",
    ):
        value = getattr(expect, field_name)
        if value is None:
            continue
        if isinstance(value, list):
            count += len(value)
        elif isinstance(value, dict):
            count += len(value)
        else:
            count += 1
    return count
