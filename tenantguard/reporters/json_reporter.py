"""JSON report generator."""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from tenantguard.results import RunResult


def _serialize(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, StrEnum):
        return str(value)
    if is_dataclass(value) and not isinstance(value, type):
        return {key: _serialize(item) for key, item in asdict(value).items()}
    if isinstance(value, list):
        return [_serialize(item) for item in value]
    if isinstance(value, dict):
        return {key: _serialize(item) for key, item in value.items()}
    return value


def render_json_report(result: RunResult) -> str:
    """Render a RunResult as formatted JSON."""
    payload = _serialize(result)
    return json.dumps(payload, indent=2, sort_keys=True)


def write_json_report(result: RunResult, output_path: Path) -> Path:
    """Write a JSON report to disk."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_json_report(result), encoding="utf-8")
    return output_path
