"""
ids/models — traffic record and alert data structures.

A :class:`TrafficRecord` is a normalized, parser-independent network flow/
connection sample. An :class:`Alert` is the output of one detection rule.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

# Severity levels (1 = low ... 5 = critical)
LOW, MEDIUM, HIGH, CRITICAL = 1, 2, 3, 5

SEVERITY_TO_NAME = {
    LOW: "low",
    MEDIUM: "medium",
    HIGH: "high",
    CRITICAL: "critical",
}


@dataclass
class TrafficRecord:
    """One network flow / connection sample."""

    timestamp: datetime
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    bytes: int
    flags: str | None = None          # e.g. SYN, ACK, PUSH, RST, FIN
    line_number: int = 0

    @property
    def is_syn(self) -> bool:
        return bool(self.flags) and "SYN" in self.flags.upper()


@dataclass
class Alert:
    """A single anomaly detection result."""

    alert_type: str
    severity: int
    src_ip: str | None
    dst_ip: str | None
    summary: str
    evidence: list[str] = field(default_factory=list)
    ts: datetime | None = None
    count: int = 1

    @property
    def level(self) -> str:
        return SEVERITY_TO_NAME.get(self.severity, "unknown")
