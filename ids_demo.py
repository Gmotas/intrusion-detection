#!/usr/bin/env python3
"""
IDS Demo — basic Intrusion Detection System that flags unusual traffic patterns.

A CLI that ingests a network-traffic feed (CSV by default) and flags anomalies:
port scans, connection floods, beacons, large transfers, protocol mismatches
and distributed scans — each with a severity rating.

Usage examples:
    python ids_demo.py examples/captured-traffic.csv
    python ids_demo.py examples/captured-traffic.csv --json
    python ids_demo.py feed.txt --input-format netflow --min-severity 3
    python ids_demo.py traffic.json --input-format json --quiet

Exit codes: 0 = normal/no alerts, 1 = alerts detected, 2 = usage/parse error.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Iterable

from ids import io
from ids.detector import Detector, DetectorConfig
from ids.models import CRITICAL, HIGH, LOW, MEDIUM
from ids.reporter import build_summary, render_json, render_report

__version__ = "1.0.0"
__author__ = "Gabriel Mota Silva"

ALL_RULES = ["port_scan", "flood", "beacon", "large_transfer", "protocol_mismatch", "distributed"]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="ids_demo",
        description="Basic intrusion detection over a network-traffic feed.",
        epilog="Exit codes: 0 = normal, 1 = alerts detected, 2 = usage/parse error.",
    )
    ap.add_argument("-i", "--input", required=True, help="Path to the traffic feed.")
    ap.add_argument("--input-format", choices=list(io.READERS.keys()), default="csv",
                    help="Feed format (default: csv).")
    ap.add_argument("--window", type=int, default=300, help="Analysis window in seconds (default 300).")
    ap.add_argument("--threshold", type=float, default=3.0,
                    help="Large-transfer z-score threshold (default 3.0).")
    ap.add_argument("--enable", action="append", choices=ALL_RULES, default=None,
                    help="Enable only these rules (repeatable).")
    ap.add_argument("--disable", action="append", choices=ALL_RULES, default=None,
                    help="Disable these rules (repeatable).")
    ap.add_argument("--min-severity", type=int, choices=[LOW, MEDIUM, HIGH, CRITICAL], default=LOW,
                    help="Minimum severity to report (default 1).")
    ap.add_argument("--top", type=int, default=0, help="Show only the top N alerts by severity.")
    ap.add_argument("--json", action="store_true", help="Emit a machine-readable JSON report.")
    ap.add_argument("--quiet", action="store_true", help="Print only the verdict line.")
    ap.add_argument("--no-color", action="store_true", help="Disable ANSI colors.")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return ap.parse_args(argv)


def read_feed(args: argparse.Namespace) -> Iterable:
    try:
        with open(args.input, encoding="utf-8", errors="replace") as fh:
            reader = io.READERS[args.input_format]
            yield from reader(fh)
    except OSError as exc:
        print(f"error: cannot read {args.input}: {exc}", file=sys.stderr)
        raise SystemExit(2)
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"error: invalid {args.input_format} feed: {exc}", file=sys.stderr)
        raise SystemExit(2)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    enabled = set(ALL_RULES)
    if args.enable:
        enabled = set(args.enable)
    if args.disable:
        enabled -= set(args.disable)

    config = DetectorConfig(
        window_seconds=args.window,
        large_transfer_z=args.threshold,
        enabled_rules=enabled,
    )
    detector = Detector(config)

    parsed = 0
    skipped = 0
    for rec in read_feed(args):
        if rec is None:
            skipped += 1
            continue
        parsed += 1
        detector.add(rec)

    alerts = detector.finalize()
    alerts = [a for a in alerts if a.severity >= args.min_severity]
    if args.top > 0:
        alerts = alerts[: args.top]

    summary = build_summary(alerts, parsed, skipped)

    if args.json:
        print(render_json(summary))
    else:
        if not args.quiet:
            print(render_report(alerts, use_color=not args.no_color))
            print(f"parsed: {parsed} records, skipped: {skipped} invalid rows")
        else:
            print("SUSPICIOUS" if alerts else "CLEAN")

    return 1 if alerts else 0


if __name__ == "__main__":
    sys.exit(main())
