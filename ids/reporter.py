"""
ids/reporter — human-readable and machine-readable output.

Renders a list of :class:`~ids.models.Alert` objects and run statistics into a
colorized console report or a JSON payload.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from typing import Any

from ids.models import Alert

_RESET = "\033[0m"
_BOLD = "\033[1m"
_RED = "\033[91m"
_YELLOW = "\033[93m"
_BLUE = "\033[94m"
_GREEN = "\033[92m"
_GRAY = "\033[90m"

_SEV_COLOR = {1: _GREEN, 2: _YELLOW, 3: _YELLOW, 5: _RED, 4: _RED}


def _paint(text: str, color: str, use_color: bool) -> str:
    return f"{color}{text}{_RESET}" if use_color else text


def build_summary(alerts: list[Alert], records_parsed: int, records_skipped: int) -> dict[str, Any]:
    by_type = Counter(a.alert_type for a in alerts)
    by_sev = Counter(a.severity for a in alerts)
    srcs = Counter(a.src_ip for a in alerts if a.src_ip)
    dsts = Counter(a.dst_ip for a in alerts if a.dst_ip)
    return {
        "analyzed_at": datetime.now().isoformat(timespec="seconds"),
        "records_parsed": records_parsed,
        "records_skipped": records_skipped,
        "total_alerts": len(alerts),
        "by_severity": {str(k): v for k, v in sorted(by_sev.items(), reverse=True)},
        "by_type": dict(by_type),
        "top_sources": dict(srcs.most_common(10)),
        "top_destinations": dict(dsts.most_common(10)),
        "alerts": [
            {
                "type": a.alert_type,
                "severity": a.severity,
                "level": a.level,
                "src": a.src_ip,
                "dst": a.dst_ip,
                "summary": a.summary,
                "count": a.count,
                "timestamp": a.ts.isoformat(timespec="seconds") if a.ts else None,
                "evidence": a.evidence,
            }
            for a in alerts
        ],
    }


def render_report(alerts: list[Alert], use_color: bool = True) -> str:
    if not alerts:
        return _paint("[+] No unusual traffic detected.\n", _GREEN, use_color)

    lines: list[str] = []
    lines.append(_paint("Intrusion Detection Report", _BOLD + _BLUE, use_color))
    lines.append(_paint("=" * 46, _GRAY, use_color))
    lines.append(_paint(f"Alerts: {len(alerts)}", _BOLD, use_color))

    by_sev = Counter(a.severity for a in alerts)
    for sev in (5, 4, 3, 2, 1):
        if by_sev.get(sev):
            label = alert_level_label(sev)
            lines.append(_paint(f"  {label:<10}: {by_sev[sev]}", _SEV_COLOR.get(sev, _GRAY), use_color))

    lines.append("")
    for idx, a in enumerate(alerts, start=1):
        color = _SEV_COLOR.get(a.severity, _GRAY)
        head = f"{idx:>2}. [{a.severity}] {a.alert_type.upper()} ({a.level})"
        lines.append(_paint(head, color, use_color))
        where = f"  src: {a.src_ip or '?'}  dst: {a.dst_ip or '?'}"
        if a.count > 1:
            where += f"  count: {a.count}"
        if a.ts:
            where += f"  at: {a.ts.isoformat(timespec='seconds')}"
        lines.append(_paint(where, _GRAY, use_color))
        lines.append(_paint(f"  {a.summary}", _GRAY, use_color))
        for ev in a.evidence[:3]:
            lines.append(_paint(f"    | {ev}", _GRAY, use_color))
        lines.append("")

    lines.append(_paint("[-] Detection complete.", _BOLD, use_color))
    return "\n".join(lines) + "\n"


def alert_level_label(severity: int) -> str:
    return {5: "critical", 4: "critical", 3: "high", 2: "medium", 1: "low"}.get(severity, "unknown")


def render_json(summary: dict[str, Any]) -> str:
    return json.dumps(summary, indent=2, ensure_ascii=False)
