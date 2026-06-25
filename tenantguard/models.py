"""Shared types and exit codes."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class ExitCode(IntEnum):
    """CLI exit codes."""

    SUCCESS = 0
    FINDINGS = 1
    INVALID_CONFIG = 2
    SAFETY_CONFIRMATION_REQUIRED = 3
    TARGET_UNAVAILABLE = 4
    INTERNAL_ERROR = 5


@dataclass
class RuntimeContext:
    """Resolved runtime values kept separate from the config model."""

    actor_tokens: dict[str, str] = field(default_factory=dict)

    def __repr__(self) -> str:
        return "RuntimeContext(actor_tokens=<redacted>)"
