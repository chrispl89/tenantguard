"""Severity levels for authorization findings."""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    """Finding severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def order(cls, severity: Severity) -> int:
        """Return numeric order for fail-on comparisons."""
        return {
            cls.LOW: 0,
            cls.MEDIUM: 1,
            cls.HIGH: 2,
            cls.CRITICAL: 3,
        }[severity]
