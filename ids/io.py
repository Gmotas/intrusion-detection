"""
ids/io — traffic feed readers.

Supports CSV (default), JSON, and a plain "netflow-like" text format. Every
reader yields :class:`~ids.models.TrafficRecord` objects and tolerates bad
rows by skipping them (reported via the caller's counter).

CSV columns expected:
    timestamp,src_ip,src_port,dst_ip,dst_port,protocol,bytes[,flags]

The timestamp may be ISO-8601 or "YYYY-MM-DD HH:MM:SS".
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from typing import Iterable

from ids.models import TrafficRecord


def _parse_ts(value: str) -> datetime:
    value = value.strip()
    # Try ISO-8601 with 'T' or space separator.
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    # Fall back to ISO-8601 with timezone.
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        raise ValueError(f"unrecognized timestamp: {value!r}")


def _row_to_record(row: dict[str, str], line_number: int) -> TrafficRecord:
    ts = _parse_ts(row["timestamp"])
    return TrafficRecord(
        timestamp=ts,
        src_ip=row["src_ip"],
        src_port=int(row["src_port"]),
        dst_ip=row["dst_ip"],
        dst_port=int(row["dst_port"]),
        protocol=row["protocol"].strip().upper(),
        bytes=int(row["bytes"]),
        flags=(row.get("flags") or "").strip() or None,
        line_number=line_number,
    )


def read_csv(source: Iterable[str]) -> Iterable[TrafficRecord]:
    """Read traffic records from an iterable of CSV lines (header included)."""
    reader = csv.DictReader(io.StringIO("".join(source)))
    for idx, row in enumerate(reader, start=1):
        if row is None or not row.get("src_ip"):
            continue
        try:
            yield _row_to_record(row, idx)
        except (KeyError, ValueError, TypeError):
            continue


def read_json(source: Iterable[str]) -> Iterable[TrafficRecord]:
    """Read traffic records from a JSON array (or an object with a 'records' key)."""
    text = "".join(source)
    data = json.loads(text)
    if isinstance(data, dict):
        data = data.get("records", [])
    for idx, row in enumerate(data, start=1):
        if not isinstance(row, dict):
            continue
        try:
            rec = TrafficRecord(
                timestamp=_parse_ts(str(row["timestamp"])),
                src_ip=str(row["src_ip"]),
                src_port=int(row["src_port"]),
                dst_ip=str(row["dst_ip"]),
                dst_port=int(row["dst_port"]),
                protocol=str(row["protocol"]).strip().upper(),
                bytes=int(row["bytes"]),
                flags=(str(row.get("flags", "")) or None),
                line_number=idx,
            )
            yield rec
        except (KeyError, ValueError, TypeError):
            continue


def read_netflow(source: Iterable[str]) -> Iterable[TrafficRecord]:
    """Read a plain whitespace-separated netflow-like text format.

    Columns: timestamp src_ip src_port dst_ip dst_port protocol bytes [flags]
    # comments and blank lines are ignored.
    """
    for idx, raw in enumerate(source, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 7:
            continue
        try:
            yield TrafficRecord(
                timestamp=_parse_ts(parts[0]),
                src_ip=parts[1],
                src_port=int(parts[2]),
                dst_ip=parts[3],
                dst_port=int(parts[4]),
                protocol=parts[5].strip().upper(),
                bytes=int(parts[6]),
                flags=parts[7] if len(parts) > 7 else None,
                line_number=idx,
            )
        except (IndexError, ValueError):
            continue


READERS = {
    "csv": read_csv,
    "json": read_json,
    "netflow": read_netflow,
}
